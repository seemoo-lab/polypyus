import os
import json

# import exceptions

from collections import defaultdict

import idc
import idaapi
import idautils
import ida_auto
import ida_bytes

SEGPERM_EXEC = 1
SEGPERM_WRITE = 2
SEGPERM_READ = 4

max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
min_ea = idc.get_inf_attr(idc.INF_MIN_EA)


def is_code(ea):
    flags = ida_bytes.get_full_flags(ea)
    return ida_bytes.is_code(flags) and ida_bytes.is_head(flags)


def is_data_start(ea):
    flags = ida_bytes.get_full_flags(ea)
    data = ida_bytes.is_data(flags)
    head = ida_bytes.is_head(flags)
    return data and head


def is_tail(ea):
    flags = ida_bytes.get_full_flags(ea)
    return ida_bytes.is_tail(flags)


def get_func_start(ea):
    return idc.get_func_attr(ea, idc.FUNCATTR_START)


def is_func(ea):
    return get_func_start(ea) != idaapi.BADADDR


def is_func_chunk(ea):
    return 0 < idc.get_fchunk_attr(ea, idc.FUNCATTR_REFQTY) < idaapi.BADADDR


def func_is_generic(ea):
    return is_func(ea) and idc.get_func_name(ea) == "sub_{0:X}".format(ea)


def create_folder(path):
    try:
        return os.makedirs(path)
    except exceptions.OSError as e:
        print(e)


def import_segments(segments):
    for start, end, perm, name in segments:
        create_section(start, end, perm, name)


def strip_names(name_dict_path):
    names = {}
    for i, func_ea in enumerate(idautils.Functions()):
        n = idc.get_func_name(func_ea)
        new_name = "f_{i}".format(i=i)
        names[n] = new_name
        idc.set_name(func_ea, new_name)
    with open(name_dict_path, "w") as f:
        json.dump(names, f, indent=4)
    return names


def import_functions(fncs, add_names=True, always_thumb=True):

    name_counter = defaultdict(int)
    imported_functions = defaultdict(set)
    cfg_conflicts = defaultdict(set)
    symbol_defects = list()
    failed_fncs = list()

    countername_Fail = 0
    counterfct_fail = 0

    def set_name(addr, name):
        # FIXME creates unnamed_178 etc. instead of proper function name in IDA 7.2 on CYW20735
        name = name.replace("sub_", "unnamed_")
        cmt = idc.get_cmt(addr, 0)
        name_cmt = "fcn.%s" % name
        if cmt:
            name_cmt = cmt + ", " + name_cmt
        idc.set_cmt(addr, name_cmt, 0)
        if not add_names:
            return
        if name.isupper():
            try:
                # hackish way to stop warning about hex import
                # FIXME leave 'sub_' intact if it already exists
                # FIXME do not set the name to the hex prologue because it has duplicates, set it to
                #       'pp_{position}' instead
                a = int(name, 16)
                """continue"""
            except ValueError:
                pass
        ok = idc.set_name(addr, name, idc.SN_CHECK)
        if not ok:
            data = (name, size, addr)
            failed_fncs.append((data, "name"))
            print("{0:#x}: cannot add name, {1}".format(addr, name))
            countername_Fail = countername_Fail + 1
        else:
            imported_functions[addr].add(name)

    for name, size, addr, thumb in fncs:
        name_counter[name] += 1

        if not always_thumb:
            idc.split_sreg_range(addr, "T", int(thumb), idc.SR_user)
        idc.create_insn(addr)

        code = is_code(addr)
        fnc = is_func(addr)
        fnc_chnk = is_func_chunk(addr)
        data = (name, size, addr)
        start = get_func_start(addr)
        generic = fnc and func_is_generic(addr)

        # BADADDR automatically finds end of fnc.
        if size >= 2 and size % 2 == 0:
            end = addr + size
        else:
            end = idaapi.BADADDR

        if not code and not (fnc or fnc_chnk):
            symbol_defects.append(data)
        elif (fnc or fnc_chnk) and not code:
            cfg_conflicts[idc.get_func_name(addr)] = (data, start)
        elif start == addr and not generic:
            set_name(addr, name)  # duplicate symbol
        elif start == addr and generic:
            set_name(addr, name)
        elif start != addr:
            if fnc_chnk:
                idc.remove_fchunk(addr, addr)
            elif fnc:
                idc.set_func_end(addr, addr)  # force previous function to end here.
            ok = idaapi.add_func(addr, end)
            if not ok:
                failed_fncs.append((data, "fnc"))
                print("{0:#x}: cannot add fnc, {1}, {2:#x}".format(addr, size, end))
                counterfct_fail = counterfct_fail + 1
            else:
                set_name(addr, name)
        else:
            failed_fncs.append((data, "unknown"))
            print(
                "{0:#x}: unknown problem - code: {1}, fnc: {2}, start {3:#x}, size {4}, end {5}".format(
                    addr, code, fnc, start, size, end
                )
            )

    ida_auto.auto_wait()
    print(
        "not added functions: {1} , not added names: {0}".format(
            countername_Fail, counterfct_fail
        )
    )
    return name_counter, imported_functions, failed_fncs, cfg_conflicts, symbol_defects


def import_objects(objs, add_names=True, always_thumb=True):
    """
    Create IDA function and data according to symbol definitions.
    Create name if add_name is True

    :param add_names: Create name for symbols?

    """

    failed_objs = []
    for name, size, addr, _ in objs:
        if not is_data_start(addr):
            if size:
                ok = idaapi.create_data(addr, idc.FF_BYTE, size, 0)
            else:
                ok = idc.create_byte(addr)
            if not ok:
                reason = "Could not create data at {addr:#x}".format(addr=addr)
                data = (name, size, addr)
                failed_objs.append((data, reason))
                """continue"""
        idc.set_cmt(addr, "obj.%s" % name, 0)
        if add_names:
            ok = idc.set_name(addr, name, idc.SN_CHECK)
            if not ok:
                reason = "Could not add name {name} at {addr:#x}".format(
                    name=name, addr=addr
                )
                data = (name, size, addr)
                failed_objs.append((data, reason))
    print("waiting for ida to finish analysis")
    ida_auto.auto_wait()
    print("ida finished import")
    return failed_objs


def clear_names():
    """for some reason deleting names seems to need several takes.
    This will loop until all names are deleted.
    """

    names = list(idautils.Names())
    while names:
        for name_ea, _ in names:
            idc.set_name(name_ea, "")  # deletes name
        ida_auto.auto_wait()
        names = list(idautils.Names())


def reset_db():
    idc.del_items(min_ea, size=max_ea - min_ea)
    idc.delete_all_segments()
    clear_names()
    ida_auto.auto_wait()


def ea_to_hex(ea):
    return "{0:#x}".format(ea)


def parse_ea(ea):
    """
    Parse effective address from string.

    :param ea: effective address
    :type ea: str

    :return: parsed effective address
    :rtype: int

    :raises ValueError: if ea is no address or bad address

    """

    addr = int(ea, 16)
    if addr > max_ea or addr < min_ea:
        raise ValueError("Bad address")
    return addr


def parse_range(start_ea, end_ea):
    """
    Parse address range

    :param start_ea: start address of range
    :type start_ea: str

    :param end_ea: end address of range
    :type end_ea: str

    :return: parsed range address
    :rtype: tuple

    .. note:: Assumes end_ea is last address inside range
    """

    start = parse_ea(start_ea)
    end = parse_ea(end_ea) + 1
    if start_ea >= end_ea:
        raise ValueError("Bad range")
    return start, end


def create_section(start_ea, end_ea, perm, name, all_thumb=True):
    """
    Create section in IDA Pro

    :param start_ea: start address of secion
    :type start_ea: str

    :param end_ea: end address of secion
    :type end_ea: str

    :param perm: Permissions of section (1:ex, 2:read, 4:write)
    :type perm: int

    :param name: name of section
    :type name: str

    :return: success
    :rtype: bool
    """

    try:
        start, end = parse_range(start_ea, end_ea)
    except ValueError:
        return False
    if idc.add_segm_ex(start, end, 0, 1, 1, 0, 0):
        idc.set_segm_name(start, name)
        idc.set_segm_attr(start, idc.SEGATTR_PERM, perm)
        if all_thumb:
            idc.split_sreg_range(start, "T", 1, idc.SR_autostart)
        return True
    return False


def ask_file_option(option_prompt, file_mask, file_promt):
    if not idaapi.ask_yn(0, option_prompt):
        return None
    return idaapi.ask_file(0, file_mask, file_promt)
