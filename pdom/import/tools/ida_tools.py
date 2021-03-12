import idc
import idaapi
import idautils
import ida_auto
import ida_bytes
import ida_name
import ida_kernwin
import ida_funcs


class IDAtools:
    max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
    min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    ida_Version = idaapi.IDA_SDK_VERSION

    MAPPED_IDS = {}

    def clean_dict():
        IDAtools.MAPPED_IDS = {}

    def is_in_ida(symbol_type, symbol_name):
        if symbol_type == "Enumeration":
            return idc.get_enum(IDAtools.clean_name(symbol_name)) != idaapi.BADADDR
        else:
            if str(IDAtools.clean_name(symbol_name)) in IDAtools.MAPPED_IDS:
                return True
            else:
                IDAtools.MAPPED_IDS[str(IDAtools.clean_name(symbol_name))] = "1"
                return False

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

    def is_func(ea):
        return IDAtools.get_func_start(ea) != idaapi.BADADDR

    def is_func_chunk(ea):
        return 0 < idc.get_fchunk_attr(ea, idc.FUNCATTR_REFQTY) < idaapi.BADADDR

    def func_is_generic(ea):
        return IDAtools.is_func(ea) and idc.get_func_name(ea) == "sub_{0:X}".format(ea)

    def is_dummy_name_by_addr(addr):
        name = idc.get_name(addr)
        dummyList = {
            "",
            "sub_",
            "locret_",
            "loc_",
            "off_",
            "seg_",
            "asc_",
            "byte_",
            "word_",
            "dword_",
            "qword_",
            "byte3_",
            "xmmword",
            "_ymmword_",
            "packreal_",
            "flt_",
            "dbl_",
            "tbyte_",
            "stru_",
            "custdata_",
            "algn_",
            "unk_",
        }
        if ida_bytes.is_unknown(ida_bytes.get_full_flags(addr)):
            return True
        for items in dummyList:
            if name.startswith(items):
                return True
        return False

    def is_dummy_name(name):
        dummyList = {
            "sub_",
            "locret_",
            "loc_",
            "off_",
            "seg_",
            "asc_",
            "byte_",
            "word_",
            "dword_",
            "qword_",
            "byte3_",
            "xmmword",
            "_ymmword_",
            "packreal_",
            "flt_",
            "dbl_",
            "tbyte_",
            "stru_",
            "custdata_",
            "algn_",
            "unk_",
        }
        for items in dummyList:
            if name.startswith(items):
                return True
        return False

    def create_function(
        fnc,
        overwrite_names,
        offset,
        add_names=True,
    ):
        def set_name(addr, name):
            if not add_names:
                return
            try:
                numericName = int(name, 16)
                return
            except ValueError:
                pass
            ok = False
            if not IDAtools.is_dummy_name(name):
                ok = idc.set_name(addr, name, idc.SN_CHECK)
            if not ok:
                data = (name, size, addr)

        name = fnc.get("name")
        addr = int(fnc.get("addr"))
        addr = addr + int(offset)
        size = int(fnc.get("size"))

        if type(addr) == int:
            idc.create_insn(addr)

            code = IDAtools.is_code(addr)
            fnc = IDAtools.is_func(addr)
            fnc_chnk = IDAtools.is_func_chunk(addr)
            start = IDAtools.get_func_start(addr)
            generic = fnc and IDAtools.func_is_generic(addr)

            if size >= 2 and size % 2 == 0:
                end = addr + size
            else:
                end = idaapi.BADADDR

            if fnc or fnc_chnk:
                ok = idc.set_func_end(addr, addr)
                if not ok:
                    pass
                    # print("{0:#x}: cannot add fnc, there still exists code, {1}, {2:#x}".format(addr, size, end))
            if IDAtools.is_dummy_name_by_addr(addr) and (
                not name.startswith("sub_") and overwrite_names
            ):
                set_name(addr, name)
            elif start == addr and overwrite_names:
                set_name(addr, name)

            elif start != addr:
                if fnc_chnk:
                    idc.remove_fchunk(addr, addr)
                elif fnc:
                    idc.set_func_end(addr, addr)  # force previous function to end here.
                ok = idaapi.add_func(addr, end)
                if ok and add_names and overwrite_names:
                    set_name(addr, name)
                if not ok:
                    print("{0:#x}: cannot add fnc, {1}, {2:#x}".format(addr, size, end))
            else:
                print(
                    "{0:#x}: unknown problem - code: {1}, fnc: {2}, start {3:#x}, size {4}, end {5}".format(
                        addr, code, fnc, start, size, end
                    )
                )

        IDAtools.ida_wait()

    def create_segement(segm, offset):
        name = segm.get("name")
        if type(segm.get("start")) != int:
            start = int(segm.get("start"), 16)
            end = int(segm.get("end"), 16)
        else:
            start = segm.get("start")
            end = segm.get("end")
        R = int(segm.get("R"))
        W = int(segm.get("W"))
        X = int(segm.get("X"))
        D = int(segm.get("D"))
        L = int(segm.get("L"))
        align = int(segm.get("align"))
        base = int(segm.get("base"))
        class_ = segm.get("class")
        ad = int(segm.get("ad"))
        T = int(segm.get("T"))
        DS = int(segm.get("DS"))

        idaapi.set_segm_end(start, start, 0)

        if idaapi.is_seg(idc.get_inf_attr(idc.INF_MAX_EA), 0):
            ok = idaapi.add_segm(base, start, 0xFFFFFFFF, name, class_)
        else:
            ok = idaapi.add_segm(
                base, start, idc.get_inf_attr(idc.INF_MAX_EA), name, class_
            )

        if ok:
            idc.set_segm_attr(start, 20, align)
            perm = 0
            if R:
                perm = perm + 4
            if W:
                perm = perm + 2
            if X:
                perm = perm + 1

            idc.set_segm_attr(start, 22, perm)

    def create_object(
        obj, overwrite_names, offset, dummy_names=True, always_thumb=True
    ):
        name = obj.get("name")
        addr = int(obj.get("addr"))
        addr = int(addr)
        size = int(obj.get("size"))

        if dummy_names:
            if IDAtools.is_dummy_name(name):
                return
        if type(addr) == int:
            if ida_bytes.is_unknown(ida_bytes.get_full_flags(addr)):
                if size:
                    ok = idaapi.create_data(addr, idc.FF_BYTE, size, 0)
                else:
                    ok = idc.create_byte(addr)
                if not ok:
                    if not ok:
                        reason = "Could not create data at {addr:#x}".format(addr=addr)
                        print(reason)

        if overwrite_names and IDAtools.is_dummy_name_by_addr(addr):
            ok = idc.set_name(addr, name, idc.SN_CHECK)
            if not ok:
                reason = "Could not add name {name} at {addr:#x}".format(
                    name=name, addr=addr
                )
                print(reason)

        IDAtools.ida_wait()

    def set_enum(name):
        if idaapi.get_enum(str(name)) != idaapi.BADADDR:
            idaapi.del_enum(idaapi.get_enum(str(name)))

        ok = idc.add_enum(-1, str(name), 1)
        if not ok:
            print("Could not add enum {name}".format(name=name))

    def set_enum_member(name, member, value):
        ok = idc.add_enum_member(idc.get_enum(str(name)), str(member), int(value), -1)
        if not ok:
            if idaapi.get_enum_member_by_name(str(member)) == idaapi.BADADDR:
                print(
                    "Could not add enum member {member} at {name}".format(
                        name=name, member=member
                    )
                )

    def set_function_type(name, TypeString, print_ERROR=False):
        ea = idaapi.get_name_ea(-1, str(name))
        if ea == idaapi.BADADDR:
            return

        ok = idc.SetType(ea, str(TypeString))
        if not ok and print_ERROR:
            print(
                "Could not add function type {name} at {ea:#x} : {TypeString}".format(
                    name=name, ea=ea, TypeString=TypeString
                )
            )

    def set_struct(name):
        if idaapi.get_struc_id(str(name)) != idaapi.BADADDR:
            idaapi.del_struc(idaapi.get_struc(idaapi.get_struc_id(name)))

        ok = idc.add_struc(-1, str(name), 0)
        if not ok:
            print("Could not add struct {name}".format(name=name))

    def set_struct_member(structname, name, flag_andTypeID, size):
        id = idc.get_struc_id(str(structname))
        offset = -1
        flag = flag_andTypeID.get("flag")
        typeid = flag_andTypeID.get("typeid")
        nbytes = size

        try:
            ok = 0
            if not idaapi.get_member_by_name(
                idaapi.get_struc(idaapi.get_struc_id(str(structname))), str(name)
            ):
                ok = idc.add_struc_member(id, str(name), offset, flag, typeid, nbytes)

            if not ok:
                if not idaapi.get_member_by_name(
                    idaapi.get_struc(idaapi.get_struc_id(str(structname))), str(name)
                ):
                    print(
                        "Could not add struct member {name} at {structname}".format(
                            name=name, structname=structname
                        )
                    )
        except:
            pass

    def set_local_type(typeString, name):
        try:
            ok = idc.set_local_type(-1, typeString + ";", 1)
        except:
            ok = False
        if not ok:
            IDAtools.MAPPED_IDS.pop(name, None)

    def set_global_data(name, TypeString):
        ea = idaapi.get_name_ea(-1, str(name))

        if ea == idaapi.BADADDR:
            return

        ok = idc.SetType(ea, str(TypeString))
        if not ok:
            print(
                "Could not add global type {name} at {ea:#x} : {TypeString}".format(
                    name=name, ea=ea, TypeString=TypeString
                )
            )

    def get_size(name, type, line):
        if type == "BasicType":
            try:
                return idc.SizeOf(idc.parse_decl(str(name), 0)[1])
            except:
                try:
                    idc.SizeOf(idc.parse_decl(str(line.get("type").get("name")), 0)[1])
                except:
                    return 1

        elif type == "ArrayType":
            subType = line.get("type")
            if not subType:
                return line.get("size")
            typeSize = IDAtools.get_size(
                str(subType.get("name")), subType.get("table"), subType
            )
            try:
                return typeSize * int(line.get("size"))
            except TypeError:
                return 1
        elif (
            type == "PointerType" or type == "ReferenceType" or type == "QualifierType"
        ):
            return 4
        elif type == "CFunctionType" or type == "CPPFunctionType":
            return 4
        elif type == "PDOMCEnumeration" or type == "PDOMCPPEnumeration":
            return idaapi.get_enum_size(idaapi.get_enum(str(name)))
        elif type == "PDOMCStructure" or type == "PDOMCPPClassType":
            return idaapi.get_struc_size(idaapi.get_struc_id(str(name)))
        elif type == "PDOMCTypedef" or type == "PDOMCPPTypedef":
            subType = line.get("type")
            if not subType:
                return 1
            return IDAtools.get_size(subType.get("name"), subType.get("table"), subType)
        else:
            raise Exception("Missing case", type)

    def get_flag_and_id(size, type):
        flag = 0x00000000
        typeid = -1

        if size == 1:
            flag = 0x00000000  # byte
        elif size == 2:
            flag = 0x10000000  # word
        elif size == 4:
            flag = 0x20000000  # dword
        elif size == 8:
            flag = 0x30000000  # qword
        try:
            typeTable = type.get("table")
        except AttributeError:
            return {"flag": flag, "typeid": typeid}

        if typeTable == "PDOMCStructure" or typeTable == "PDOMCPPClassType":
            flag = 0x60000000
            typeid = idaapi.get_struc_id(str(type.get("name")))
            return {"flag": flag, "typeid": typeid}
        elif typeTable == "PDOMCEnumeration" or typeTable == "PDOMCPPEnumeration":
            typeid = idaapi.get_enum_size(idaapi.get_enum(str(type.get("name"))))
        elif typeTable == "PDOMCTypedef" or typeTable == "PDOMCPPTypedef":
            return IDAtools.get_flag_and_id(size, type.get("type"))

        return {"flag": flag, "typeid": typeid}

    def get_names():
        list = []
        for names in idautils.Names():
            if not IDAtools.is_dummy_name(names[1]):
                list.append(names[1])
        return list

    def get_func_names():
        names = []
        for ea in idautils.Functions():
            name = ida_funcs.get_func_name(ea)
            if not name.startswith("sub_"):
                names.append(name)
        return names

    def get_func_start(ea):
        return idc.get_func_attr(ea, idc.FUNCATTR_START)

    def clean_name(name):
        name = name.replace("}", "")
        name = name.replace("{", "")
        name = name.replace(":", "_")
        name = name.replace(".", "_")
        return name

    def ea_to_hex(ea):
        return "{0:#x}".format(ea)

    def parse_ea(ea):
        addr = int(ea, 16)
        if addr > max_ea or addr < min_ea:
            raise ValueError("Bad address")
        return addr

    def ida_wait():
        ida_auto.auto_wait()
