# -*- coding: utf-8 -*-
"""
Import different annotation formats
"""
import csv
import itertools as it
import struct
from dataclasses import dataclass
from enum import IntEnum, auto
from operator import itemgetter
from pathlib import Path
from typing import Iterable, List, NewType, Tuple

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from loguru import logger

Name = NewType("Name", str)
Addr = NewType("Addr", int)
Size = NewType("Size", int)
Mode = NewType("ArmExMode", int)
FunctionBounds = Tuple[Name, Addr, Addr, Mode]
CSV_KEYS_SHORT = ["name", "addr", "size"]
CSV_KEYS_LONG = CSV_KEYS_SHORT + ["mode", "type"]

csv.register_dialect("space_delimiter", delimiter=" ", quoting=csv.QUOTE_NONE)


class FunctionMode(IntEnum):
    ARM_32 = 0
    THUMB_32 = 1
    ARM_64 = 2


class FileType(IntEnum):
    """Filetype discriminator"""

    CSV = auto()
    ELF = auto()
    SYMDEFS = auto()
    unknown = auto()


def guess_type(filename: Path):
    """
    Guesses the filetype for annotation files
    """
    ext = filename.suffix
    if ext.lower() == ".csv":
        with open(filename, "r") as csv_file:
            dialect = csv.Sniffer().sniff(csv_file.read(1024))
            csv_file.seek(0)
            reader = csv.DictReader(csv_file, dialect=dialect)
            if all(key in reader.fieldnames for key in CSV_KEYS_SHORT):
                return FileType.CSV
    if ext in (".elf", ""):
        try:
            with open(filename, "rb") as stream:
                elf_file = ELFFile(stream)
                return FileType.ELF
        except ELFError:
            pass
    if ext in (".symdefs"):
        return FileType.SYMDEFS
    if not ext:
        with open(filename, "r") as symdefs:
            head = next(symdefs)
            if head.startswith(SYMDEFS_HEADER):
                return FileType.SYMDEFS
    logger.info(f"filetype of {filename} not known/supported")
    return FileType.unknown


def get_elf_symbols(elf_path: Path) -> Iterable[Tuple[str, int, int]]:
    """get_elf_symbols extract name, addr and type of symbol.

	Args:
        elf_path: the path to the elf file
    Returns:
        name, addr and type of symbols
    """

    with open(elf_path, "rb") as stream:
        elffile = ELFFile(stream)
        section = elffile.get_section_by_name(".symtab")
        for sym in section.iter_symbols():
            yield sym.name, sym["st_value"], sym["st_size"], sym["st_info"]["type"]


def filter_elf_functions(
    symbols: Iterable[Tuple[str, int, int, str]]
) -> Iterable[FunctionBounds]:
    """
    note:
        Adjusts thumb addresses by -1
    """
    func_type = "STT_FUNC"
    for name, start, size, type_ in symbols:
        if type_ != func_type:
            continue
        yield name, start, size, type_


def postprocess_elf_functions(
    symbols: Iterable[FunctionBounds],
) -> Iterable[FunctionBounds]:
    for name, start, size, _ in symbols:
        mode = start % 2
        if mode == 1:
            start -= 1
            if size % 2 == 1:
                size += 1
        yield name, start, size, mode


def estimate_symbol_size(
    symbols: Iterable[Tuple[str, int, int, str]]
) -> Iterable[Tuple[str, int, int, str]]:
    """estimate_symbol_size adds size estimate to symbol data based on the
    next items address.

    Note:
        Expects symbols to be sorted ascending by address

	Args:
        symbols: symbols consisting of name and start address, symbol type

	Returns:
        symbols with size estimation
    """

    symbols = list(symbols)
    length = len(symbols)
    for i, symb in enumerate(symbols):
        name, start, size, type_ = symb
        if size == 0 or size is None:
            other_pos = start
            k = 1
            while other_pos == start and i + k < length:
                other_pos = symbols[i + k][1]
                k += 1
            size = other_pos - start
        yield name, start, size, type_

    # funcs, end = it.tee(symbols)
    # next(end, None)  # Advance by 1
    # for f_s, f_e in zip(funcs, end):
    #     name, start, size, type_ = f_s
    #     _, end, _ = f_e
    #     size = end - start - 1
    #     yield name, start, size, type_


def parse_elf_functions(elf_path: Path) -> Iterable[FunctionBounds]:
    """parse_elf_functions reads the symtab from given elf file,
    estimates function boundaries by the next symbols addr and returns
    all function symbols.
    """
    sym = get_elf_symbols(elf_path)
    sym = filter_elf_functions(sym)
    meta = estimate_symbol_size(sym)
    yield from postprocess_elf_functions(meta)


def get_csv_functions(csv_path: Path) -> Iterable[FunctionBounds]:
    """parse_csv_functions reads a csv file with columns for name, start, size, type
    and returns all rows of type FUNC"""
    with open(csv_path, "r") as csv_file:
        dialect = csv.Sniffer().sniff(csv_file.read(1024))
        csv_file.seek(0)
        reader = csv.DictReader(csv_file, dialect=dialect)
        for row in reader:
            if row.get("type", "FUNC") != "FUNC":
                continue
            addr = int(row["addr"], 16)
            try:
                mode = row.get("mode", None)
                mode = getattr(FunctionMode, mode)
            except (AttributeError, TypeError):
                mode = addr % 2
                if mode == 1:
                    addr -= 1
            size = int(row["size"])
            yield row["name"], addr, size, mode


def parse_csv_functions(csv_path: Path) -> Iterable[FunctionBounds]:
    functions = get_csv_functions(csv_path)
    yield from estimate_symbol_size(functions)


SYMDEFS_HEADER = "#<SYMDEFS>#"


def get_symdefs(path: Path):
    with open(path, "r") as symdefs:
        for i, row in enumerate(symdefs):
            if i == 0 and row.startswith(SYMDEFS_HEADER):
                continue
            row = row.strip()
            if not row or row[0] in (";", "#"):
                continue
            try:
                value, flag, name = row.split()
                yield name, int(value, 16), 0, flag
            except ValueError:
                continue


SYMDEF_FLAG_MAPPING = dict(
    X=FunctionMode.ARM_64, A=FunctionMode.ARM_32, T=FunctionMode.THUMB_32
)


def parse_symdef_flag(
    symdef_meta=Iterable[Tuple[str, int, int, str]]
) -> Iterable[FunctionBounds]:
    for name, addr, size, flag in symdef_meta:
        if flag in ("D", "N"):
            continue
        try:
            if flag == "T":
                if addr % 2 == 1:
                    addr -= 1
                    if size % 2 == 1:
                        size += 1
            yield name, addr, size, SYMDEF_FLAG_MAPPING[flag]
        except KeyError:
            logger.warning(f"Unknown symdefs flag {flag} for {name}@{addr:#08X}")
            continue


def parse_symdefs_functions(path: Path):
    """
    Implemented following this documentation
    https://developer.arm.com/docs/101754/0613/armlink-reference/accessing-and-managing-symbols-with-armlink/access-symbols-in-another-image/symdefs-file-format
    """
    symdefs = get_symdefs(path)
    meta = estimate_symbol_size(symdefs)
    yield from parse_symdef_flag(meta)


class HCD_TYPES(IntEnum):
    HCI_CMD = 1
    ACL_DATA = 2
    SCO_DATA = 3
    HCI_EVENT = 4
    BCM_DBG = 7  # vendor specific: broadcom


class EOF(Exception):
    pass


def _read_raise_eof(stream, size):
    assert size > 0
    data = stream.read(size)
    if len(data) < size:
        raise EOF
    return data


_hci_cmd_header_struct = struct.Struct("<HB")
_hci_cmd_header_size = _hci_cmd_header_struct.size
_hci_cmd_write_ram_opcode = 0xFC4C


class HCI_CMD:
    def __init__(self, header: bytes):
        self.opcode, self.plen = _hci_cmd_header_struct.unpack(header)
        self.raw_payload = b""
        self.payload = None

    def handle_payload(self):
        if self.opcode == _hci_cmd_write_ram_opcode:
            self.payload = parse_tlv_list(self.raw_payload, self.plen)

    def __str__(self):
        if self.payload is None:
            return f"{HCI_CMD_STR[self.opcode]}\t{self.plen}\t{self.raw_payload.hex()}"
        else:
            return f"{HCI_CMD_STR[self.opcode]}\t{self.plen}\t{self.payload}"


_rompatch_struct = struct.Struct("<BII4s2x4s")
_rompatch_size = _rompatch_struct.size


@dataclass
class RomPatch:
    slot: int
    target_address: int
    value: bytes
    unknown: bytes

    def __str__(self):
        return f"Rom Patch[{self.slot}] @0x{self.target_address:X} '{self.value.hex()}'"

    @classmethod
    def from_bytes(cls, data: bytes):
        return cls(*_rompatch_struct.unpack(data))


_rampatch_struct = struct.Struct("<I")
_rampatch_size = _rampatch_struct.size


@dataclass
class RamPatch:
    target_address: int
    value: bytes

    @classmethod
    def from_bytes(cls, data: bytes):
        target_address = _rampatch_struct.unpack(data[:_rampatch_size])
        value = data[_rampatch_size:]
        return cls(target_address, value)

    def __str__(self):
        return f"Ram Patch @0x{self.target_address:X} '{self.value.hex()}'"


def parse_tlv_list(data: bytes, plen: int) -> List["TLV"]:
    tlv_list = []
    data_len = plen - 4
    assert len(data) == plen
    addr = struct.unpack("<I", data[:4])[0]
    print(f"0x{addr:X}")
    offset = 4
    while data_len >= _tlv_header_size:
        tlv = TLV(data[offset : offset + _tlv_header_size])
        print(tlv.plen, data_len, _tlv_header_size)
        offset += _tlv_header_size
        data_len -= _tlv_header_size
        if data_len < tlv.plen:
            break
            raise Exception("Firmware is corrupted")
        tlv.raw_payload = data[offset : offset + tlv.plen]
        if tlv.tlv_type == TLV_TYPES.PatchRom32b:
            tlv.payload = RomPatch.from_bytes(tlv.raw_payload)
        elif tlv.tlv_type == TLV_TYPES.PatchRam:
            tlv.payload = RamPatch.from_bytes(tlv.raw_payload)
        data_len -= tlv.plen
        offset += tlv.plen
        tlv_list.append(tlv)
    if tlv_list:
        return tlv_list
    else:
        return None


_tlv_header_struct = struct.Struct("<BH")
_tlv_header_size = _tlv_header_struct.size


class TLV:
    def __init__(self, header: bytes):
        self.tlv_type, self.plen = _tlv_header_struct.unpack(header)
        try:
            self.tlv_type = TLV_TYPES(self.tlv_type)
        except ValueError:
            pass
        self.raw_payload = b""
        self.payload = None

    def __str__(self):
        if self.payload is None:
            return f"TLV {self.tlv_type}\t{self.plen}\t{self.raw_payload.hex()}"
        else:
            return f"TLV {self.tlv_type}\t{self.plen}\t{self.payload}"


class TLV_TYPES(IntEnum):
    Reboot = 0x02
    PatchRom32b = 0x08
    PatchRam = 0x0A
    SetDefaultBTDAddr = 0x40
    SetLocalDevName = 0x41
    EndTLVList = 0xFE


HCI_CMD_STR = {
    0x0401: "COMND Inquiry",
    0x0402: "COMND Inquiry_Cancel",
    0x0403: "COMND Periodic_Inquiry_Mode",
    0x0404: "COMND Exit_Periodic_Inquiry_Mode",
    0x0405: "COMND Create_Connection",
    0x0406: "COMND Disconnect",
    0x0408: "COMND Create_Connection_Cancel",
    0x0409: "COMND Accept_Connection_Request",
    0x040A: "COMND Reject_Connection_Request",
    0x040B: "COMND Link_Key_Request_Reply",
    0x040C: "COMND Link_Key_Request_Negative_Reply",
    0x040D: "COMND PIN_Code_Request_Reply",
    0x040E: "COMND PIN_Code_Request_Negative_Reply",
    0x040F: "COMND Change_Connection_Packet_Type",
    0x0411: "COMND Authentication_Requested",
    0x0413: "COMND Set_Connection_Encryption ",
    0x0415: "COMND Change_Connection_Link_Key",
    0x0417: "COMND Master_Link_Key",
    0x0419: "COMND Remote_Name_Request",
    0x041A: "COMND Remote_Name_Request_Cancel",
    0x041B: "COMND Read_Remote_Supported_Features",
    0x041C: "COMND Read_Remote_Extended_Features",
    0x041D: "COMND Read_Remote_Version_Information",
    0x041F: "COMND Read_Clock_Offset",
    0x0420: "COMND Read_LMP_Handle",
    0x0428: "COMND Setup_Synchronous_Connection",
    0x0429: "COMND Accept_Synchronous_Connection_Request",
    0x042A: "COMND Reject_Synchronous_Connection_Request",
    0x042B: "COMND IO_Capability_Request_Reply",
    0x042C: "COMND User_Confirmation_Request_Reply",
    0x042D: "COMND User_Confirmation_Request_Negative_Reply",
    0x042E: "COMND User_Passkey_Request_Reply",
    0x042F: "COMND User_Passkey_Request_Negative_Reply",
    0x0430: "COMND Remote_OOB_Data_Request_Reply",
    0x0433: "COMND Remote_OOB_Data_Request_Negative_Reply",
    0x0434: "COMND IO_Capability_Request_Negative_Reply",
    0x0435: "COMND Create_Physical_Link",
    0x0436: "COMND Accept_Physical_Link",
    0x0437: "COMND Disconnect_Physical_Link",
    0x0438: "COMND Create_Logical_Link",
    0x0439: "COMND Accept_Logical_Link",
    0x043A: "COMND Disconnect_Logical_Link",
    0x043B: "COMND Logical_Link_Cancel",
    0x043C: "COMND Flow_Spec_Modify",
    0x043D: "COMND Enhanced_Setup_Synchronous_Connection",
    0x043E: "COMND Enhanced_Accept_Synchronous_Connection_Request",
    0x043F: "COMND Truncated_Page",
    0x0440: "COMND Truncated_Page_Cancel",
    0x0441: "COMND Set_Connectionless_Slave_Broadcast",
    0x0442: "COMND Set_Connectionless_Slave_Broadcast_Broadcast_Receive",
    0x0443: "COMND Start_Synchronization_Train",
    0x0444: "COMND Receive_Synchronization_Train",
    0x0445: "COMND Remote_OOB_Extended_Data_Request_Reply",
    0x0801: "COMND Hold_Mode",
    0x0803: "COMND Sniff_Mode",
    0x0804: "COMND Exit_Sniff_Mode",
    0x0805: "COMND Park_State",
    0x0806: "COMND Exit_Park_State",
    0x0807: "COMND QoS_Setup",
    0x0809: "COMND Role_Discovery",
    0x080B: "COMND Switch_Role",
    0x080C: "COMND Read_Link_Policy_Settings",
    0x080D: "COMND Write_Link_Policy_Settings",
    0x080E: "COMND Read_Default_Link_Policy_Settings",
    0x080F: "COMND Write_Default_Link_Policy_Settings",
    0x0810: "COMND Flow_Specification",
    0x0811: "COMND Sniff_Subrating",
    0x0C01: "COMND Set_Event_Mask",
    0x0C03: "COMND Reset",
    0x0C05: "COMND Set_Event_Filter",
    0x0C08: "COMND Flush",
    0x0C09: "COMND Read_PIN_Type",
    0x0C0A: "COMND Write_PIN_Type",
    0x0C0B: "COMND Create_New_Unit_Key",
    0x0C0D: "COMND Read_Stored_Link_Key",
    0x0C11: "COMND Write_Stored_Link_Key",
    0x0C12: "COMND Delete_Stored_Link_Key",
    0x0C13: "COMND Write_Local_Name",
    0x0C14: "COMND Read_Local_Name",
    0x0C15: "COMND Read_Connection_Accept_Timeout",
    0x0C16: "COMND Write_Connection_Accept_Timeout",
    0x0C17: "COMND Read_Page_Timeout",
    0x0C18: "COMND Write_Page_Timeout",
    0x0C19: "COMND Read_Scan_Enable",
    0x0C1A: "COMND Write_Scan_Enable",
    0x0C1B: "COMND Read_Page_Scan_Activity",
    0x0C1C: "COMND Write_Page_Scan_Activity",
    0x0C1D: "COMND Read_Inquiry_Scan_Activity",
    0x0C1E: "COMND Write_Inquiry_Scan_Activity",
    0x0C1F: "COMND Read_Authentication_Enable",
    0x0C20: "COMND Write_Authentication_Enable",
    0x0C23: "COMND Read_Class_of_Device",
    0x0C24: "COMND Write_Class_of_Device",
    0x0C25: "COMND Read_Voice_Setting",
    0x0C26: "COMND Write_Voice_Setting",
    0x0C27: "COMND Read_Automatic_Flush_Timeout",
    0x0C28: "COMND Write_Automatic_Flush_Timeout",
    0x0C29: "COMND Read_Num_Broadcast_Retransmissions",
    0x0C30: "COMND Write_Num_Broadcast_Retransmissions",
    0x0C2B: "COMND Read_Hold_Mode_Activity",
    0x0C2C: "COMND Write_Hold_Mode_Activity",
    0x0C2D: "COMND Read_Transmit_Power_Level",
    0x0C2E: "COMND Read_Synchronous_Flow_Control_Enable",
    0x0C2F: "COMND Write_Synchronous_Flow_Control_Enable",
    0x0C31: "COMND Set_Controller_To_Host_Flow_Control",
    0x0C33: "COMND Host_Buffer_Size",
    0x0C35: "COMND Host_Number_Of_Completed_Packets",
    0x0C36: "COMND Read_Link_Supervision_Timeout",
    0x0C37: "COMND Write_Link_Supervision_Timeout",
    0x0C38: "COMND Read_Number_Of_Supported_IAC",
    0x0C39: "COMND Read_Current_IAC_LAP",
    0x0C3A: "COMND Write_Current_IAC_LAP",
    0x0C3F: "COMND Set_AFH_Host_Channel_Classification",
    0x0C42: "COMND Read_Inquiry_Scan_Type",
    0x0C43: "COMND Write_Inquiry_Scan_Type",
    0x0C44: "COMND Read_Inquiry_Mode",
    0x0C45: "COMND Write_Inquiry_Mode",
    0x0C46: "COMND Read_Page_Scan_Type",
    0x0C47: "COMND Write_Page_Scan_Type",
    0x0C48: "COMND Read_AFH_Channel_Assessment_Mode",
    0x0C49: "COMND Write_AFH_Channel_Assessment_Mode",
    0x0C51: "COMND Read_Extended_Inquiry_Response",
    0x0C52: "COMND Write_Extended_Inquiry_Response",
    0x0C53: "COMND Refresh_Encryption_Key",
    0x0C55: "COMND Read_Simple_Pairing_Mode",
    0x0C56: "COMND Write_Simple_Pairing_Mode",
    0x0C57: "COMND Read_Local_OOB_Data",
    0x0C58: "COMND Read_Inquiry_Response_Transmit_Power_Level",
    0x0C59: "COMND Write_Inquiry_Response_Transmit_Power_Level",
    0x0C60: "COMND Send_Key_Press_Notification",
    0x0C5A: "COMND Read_Default_Erroneous_Data_Reporting",
    0x0C5B: "COMND Write_Default_Erroneous_Data_Reporting",
    0x0C5F: "COMND Enhanced_Flush",
    0x0C61: "COMND Read_Logical_Link_Accept_Timeout",
    0x0C62: "COMND Write_Logical_Link_Accept_Timeout",
    0x0C63: "COMND Set_Event_Mask_Page_2",
    0x0C64: "COMND Read_Location_Data",
    0x0C65: "COMND Write_Location_Data",
    0x0C66: "COMND Read_Flow_Control_Mode",
    0x0C67: "COMND Write_Flow_Control_Mode",
    0x0C68: "COMND Read_Enhance_Transmit_Power_Level",
    0x0C69: "COMND Read_Best_Effort_Flush_Timeout",
    0x0C6A: "COMND Write_Best_Effort_Flush_Timeout",
    0x0C6B: "COMND Short_Range_Mode",
    0x0C6C: "COMND Read_LE_Host_Support",
    0x0C6D: "COMND Write_LE_Host_Support",
    0x0C6E: "COMND Set_MWS_Channel_Parameters",
    0x0C6F: "COMND Set_External_Frame_Configuration",
    0x0C70: "COMND Set_MWS_Signaling",
    0x0C71: "COMND Set_MWS_Transport_Layer",
    0x0C72: "COMND Set_MWS_Scan_Frequency_Table",
    0x0C73: "COMND Set_MWS_PATTERN_Configuration",
    0x0C74: "COMND Set_Reserved_LT_ADDR",
    0x0C75: "COMND Delete_Reserved_LT_ADDR",
    0x0C76: "COMND Set_Connectionless_Slave_Broadcast_Data",
    0x0C77: "COMND Read_Synchronization_Train_Parameters",
    0x0C78: "COMND Write_Synchronization_Train_Parameters",
    0x0C79: "COMND Read_Secure_Connections_Host_Support",
    0x0C7A: "COMND Write_Secure_Connections_Host_Support",
    0x0C7B: "COMND Read_Authenticated_Payload_Timeout",
    0x0C7C: "COMND Write_Authenticated_Payload_Timeout",
    0x0C7D: "COMND Read_Local_OOB_Extended_Data",
    0x0C7E: "COMND Read_Extended_Page_Timeout",
    0x0C7F: "COMND Write_Extended_Page_Timeout",
    0x0C80: "COMND Read_Extended_Inquiry_Length",
    0x0C81: "COMND Write_Extended_Inquiry_Length",
    0x1001: "COMND Read_Local_Version_Information",
    0x1002: "COMND Read_Local_Supported_Commands",
    0x1003: "COMND Read_Local_Supported_Features",
    0x1004: "COMND Read_Local_Extended_Features",
    0x1005: "COMND Read_Buffer_Size",
    0x1009: "COMND Read_BD_ADDR",
    0x100A: "COMND Read_Data_Block_Size",
    0x100B: "COMND Read_Local_Supported_Codecs",
    0x1401: "COMND Read_Failed_Contact_Counter",
    0x1402: "COMND Reset_Failed_Contact_Counter",
    0x1403: "COMND Read_Link_Quality",
    0x1405: "COMND Read_RSSI",
    0x1406: "COMND Read_AFH_Channel_Map",
    0x1407: "COMND Read_Clock",
    0x1408: "COMND Encryption_Key_Size",
    0x1409: "COMND Read_Local_AMP_Info",
    0x140A: "COMND Read_Local_AMP_ASSOC",
    0x140B: "COMND Write_Remote_AMP_ASSOC",
    0x140C: "COMND Get_MWS_Transport_Layer_Configuration",
    0x140D: "COMND Set_Triggered_Clock_Capture",
    0x1801: "COMND Read_Loopback_Mode",
    0x1802: "COMND Write_Loopback_Mode",
    0x1803: "COMND Enable_Device_Under_Test_Mode",
    0x1804: "COMND Write_Simple_Pairing_Debug_Mode",
    0x1807: "COMND Enable_AMP_Receiver_Reports",
    0x1808: "COMND AMP_Test_End",
    0x1809: "COMND AMP_Test",
    0x180A: "COMND Write_Secure_Connection_Test_Mode",
    0x2001: "COMND LE_Set_Event_Mask",
    0x2002: "COMND LE_Read_Buffer_Size",
    0x2003: "COMND LE_Read_Local_Supported_Features",
    0x2005: "COMND LE_Set_Random_Address",
    0x2006: "COMND LE_Set_Advertising_Parameters",
    0x2007: "COMND LE_Read_Advertising_Channel_Tx_Power",
    0x2008: "COMND LE_Set_Advertising_Data",
    0x2009: "COMND LE_Set_Scan_Responce_Data",
    0x200A: "COMND LE_Set_Advertise_Enable",
    0x200B: "COMND LE_Set_Set_Scan_Parameters",
    0x200C: "COMND LE_Set_Scan_Enable",
    0x200D: "COMND LE_Create_Connection",
    0x200E: "COMND LE_Create_Connection_Cancel ",
    0x200F: "COMND LE_Read_White_List_Size",
    0x2010: "COMND LE_Clear_White_List",
    0x2011: "COMND LE_Add_Device_To_White_List",
    0x2012: "COMND LE_RemoveDevice_From_White_List",
    0x2013: "COMND LE_Connection_Update",
    0x2014: "COMND LE_Set_Host_Channel_Classification",
    0x2015: "COMND LE_Read_Channel_Map",
    0x2016: "COMND LE_Read_Remote_Used_Features",
    0x2017: "COMND LE_Encrypt",
    0x2018: "COMND LE_Rand",
    0x2019: "COMND LE_Start_Encryption",
    0x201A: "COMND LE_Long_Term_Key_Request_Reply",
    0x201B: "COMND LE_Long_Term_Key_Request_Negative_Reply",
    0x201C: "COMND LE_Read_Supported_States",
    0x201D: "COMND LE_Receiver_Test",
    0x201E: "COMND LE_Transmitter_Test",
    0x201F: "COMND LE_Test_End",
    0x2020: "COMND LE_Remote_Connection_Parameter_Request_Reply",
    0x2021: "COMND LE_Remote_Connection_Parameter_Request_Negative_Reply",
    # Function names extracted from CYW20735 / Packet Logger 9 / bluez source / BCM20703A2 Symbols
    0xFC00: "COMND VSC_CustomerExtension",
    0xFC01: "COMND VSC_WriteBdAddr",
    0xFC02: "COMND VSC_DumpSRAM",
    0xFC03: "COMND VSC_ChannelClassConfig",
    0xFC04: "COMND VSC_READ_PAGE_SCAN_REPETITION_MODE",
    0xFC05: "COMND VSC_WRITE_PAGE_SCAN_REPETITION_MODE",
    0xFC06: "COMND VSC_READ_PAGE_RESPONSE_TIMEOUT",
    0xFC07: "COMND VSC_WRITE_PAGE_RESPONSE_TIMEOUT",
    0xFC08: "COMND VSC_BTLinkQualityMode",  # VSC_READ_NEW_CONNECTION_TIMEOUT
    0xFC09: "COMND VSC_WRITE_NEW_CONNECTION_TIMEOUT",
    0xFC0A: "COMND VSC_Super_Peek_Poke",
    0xFC0B: "COMND VSC_WriteLocalSupportedFeatures",
    0xFC0C: "COMND VSC_Super_Duper_Peek_Poke",
    0xFC0D: "COMND VSC_RSSI_HISTORY",
    0xFC0E: "COMND VSC_SetLEDGlobalCtrl",
    0xFC0F: "COMND VSC_FORCE_HOLD_MODE",
    0xFC10: "COMND VSC_Commit_BDAddr",
    0xFC12: "COMND VSC_WriteHoppingChannels",
    0xFC13: "COMND VSC_SleepForeverMode",
    0xFC14: "COMND VSC_SetCarrierFrequencyArm",
    0xFC16: "COMND VSC_SetEncryptionKeySize",
    0xFC17: "COMND VSC_Invalidate_Flash_and_Reboot",
    0xFC18: "COMND VSC_Update_UART_Baud_Rate",
    0xFC19: "COMND VSC_GpioConfigAndWrite",
    0xFC1A: "COMND VSC_GpioRead",
    0xFC1B: "COMND VSC_SetTestModeType",
    0xFC1C: "COMND VSC_WriteScoPcmInterfaceParam",
    0xFC1D: "COMND VSC_ReadScoPcmIntParam",
    0xFC1E: "COMND VSC_WritePcmDataFormatParam",
    0xFC1F: "COMND VSC_ReadPcmDataFormatParam",
    0xFC20: "COMND VSC_WriteComfortNoiseParam",
    0xFC22: "COMND VSC_WriteScoTimeSlot",
    0xFC23: "COMND VSC_ReadScoTimeSlot",
    0xFC24: "COMND VSC_WritePcmLoopbackModed",
    0xFC25: "COMND VSC_ReadPcmLoopbackModed",
    0xFC26: "COMND VSC_SetTransmitPower",
    0xFC27: "COMND VSC_SetSleepMode",
    0xFC28: "COMND VSC_ReadSleepMode",
    0xFC29: "COMND VSC_SleepmodeCommand",
    0xFC2A: "COMND VSC_HandleDelayPeripheralSCOStartup",
    0xFC2B: "COMND VSC_WriteReceiveOnly",
    0xFC2D: "COMND VSC_RfConfigSettings",
    0xFC2E: "COMND VSC_HandleDownload_Minidriver",
    0xFC2F: "COMND VSC_CrystalPpm",
    0xFC32: "COMND VSC_SetAFHBehavior",
    0xFC33: "COMND VSC_ReadBtwSecurityKey",
    0xFC34: "COMND VSC_EnableRadio",
    0xFC35: "COMND VSC_Cosim_Set_Mode",
    0xFC36: "COMND VSC_GetHIDDeviceList",
    0xFC37: "COMND VSC_AddHIDDevice",
    0xFC39: "COMND VSC_RemoveHIDDevice",
    0xFC3A: "COMND VSC_EnableTca",
    0xFC3B: "COMND VSC_EnableUSBHIDEmulation",
    0xFC3C: "COMND VSC_WriteRfProgrammingTable",
    0xFC40: "COMND VSC_ReadCollaborationMode",
    0xFC41: "COMND VSC_WriteCollaborationMode",
    0xFC43: "COMND VSC_WriteRFAttenuationTable",
    0xFC44: "COMND VSC_ReadUARTClockSetting",
    0xFC45: "COMND VSC_WriteUARTClockSetting",
    0xFC46: "COMND VSC_SetSleepClockAccuratyAndSettlingTime",
    0xFC47: "COMND VSC_ConfigureSleepMode",
    0xFC48: "COMND VSC_ReadRawRssi",
    0xFC49: "COMND VSC_ChannelClassConfig",
    0xFC4C: "COMND VSC_Write_RAM",
    0xFC4D: "COMND VSC_Read_RAM",
    0xFC4E: "COMND VSC_Launch_RAM",
    0xFC4F: "COMND VSC_InstallPatches",
    0xFC51: "COMND VSC_RadioTxTest",
    0xFC52: "COMND VSC_RadioRxTest",
    0xFC54: "COMND VSC_DUT_LoopbackTest",
    0xFC56: "COMND VSC_EnhancedRadioRxTest",
    0xFC57: "COMND VSC_WriteHighPriorityConnection",
    0xFC58: "COMND VSC_SendLmpPdu",
    0xFC59: "COMND VSC_PortInformationEnable",
    0xFC5A: "COMND VSC_ReadBtPortPidVid",
    0xFC5B: "COMND VSC_Read2MBitFlashCrc",
    0xFC5C: "COMND VSC_FactoryCommitProductionTestFlag",
    0xFC5D: "COMND VSC_ReadProductionTestFlag",
    0xFC5E: "COMND VSC_WritePcmMuteParam",
    0xFC5F: "COMND VSC_ReadPcmMuteParam",
    0xFC61: "COMND VSC_WritePcmPins",
    0xFC62: "COMND VSC_ReadPcmPins",
    0xFC6D: "COMND VSC_WriteI2sPcmInterface",
    0xFC6E: "COMND VSC_ReadControllerFeatures",
    0xFC6F: "COMND VSC_WriteComfortNoiseParam",
    0xFC71: "COMND VSC_WriteRamCompressed",  # maybe .hcd only
    0xFC78: "COMND VSC_CALCULATE_CRC",
    0xFC79: "COMND VSC_ReadVerboseConfigVersionInfo",
    0xFC7A: "COMND VSC_TRANSPORT_SUSPEND",
    0xFC7B: "COMND VSC_TRANSPORT_RESUME",
    0xFC7C: "COMND VSC_BasebandFlowControlOverride",
    0xFC7D: "COMND VSC_WriteClass15PowerTable",
    0xFC7E: "COMND VSC_EnableWbs",
    0xFC7F: "COMND VSC_WriteVadMode",
    0xFC80: "COMND VSC_ReadVadMode",
    0xFC81: "COMND VSC_WriteEcsiConfig",
    0xFC82: "COMND VSC_FM_TX_COMMAND",
    0xFC83: "COMND VSC_WriteDynamicScoRoutingChange",
    0xFC84: "COMND VSC_READ_HID_BIT_ERROR_RATE",
    0xFC85: "COMND VSC_EnableHciRemoteTest",
    0xFC8A: "COMND VSC_CALIBRATE_BANDGAP",
    0xFC8B: "COMND VSC_UipcOverHci",  # Write Coexistence Tri State Enabled
    0xFC8C: "COMND VSC_READ_ADC_CHANNEL",
    0xFC90: "COMND VSC_CoexBandwidthStatistics",
    0xFC91: "COMND VSC_ReadPmuConfigFlags",
    0xFC92: "COMND VSC_WritePmuConfigFlags",
    0xFC93: "COMND VSC_ARUBA_CTRL_MAIN_STATUS_MON",
    0xFC94: "COMND VSC_CONTROL_AFH_ACL_SETUP",
    0xFC95: "COMND VSC_ARUBA_READ_WRITE_INIT_PARAM",
    0xFC96: "COMND VSC_INTERNAL_CAPACITOR_TUNING",
    0xFC97: "COMND VSC_BFC_DISCONNECT",
    0xFC98: "COMND VSC_BFC_SEND_DATA",
    0xFC9A: "COMND VSC_COEX_WRITE_WIMAX_CONFIGURATION",
    0xFC9B: "COMND VSC_BFC_POLLING_ENABLE",
    0xFC9C: "COMND VSC_BFC_RECONNECTABLE_DEVICE",
    0xFC9D: "COMND VSC_CONDITIONAL_SCAN_CONFIGURATION",
    0xFC9E: "COMND VSC_PacketErrorInjection",
    0xFCA0: "COMND VSC_WriteRfReprogrammingTableMasking",
    0xFCA1: "COMND VSC_BLPM_ENABLE",
    0xFCA2: "COMND VSC_ReadAudioRouteInfo",
    0xFCA3: "COMND VSC_EncapsulatedHciCommand",
    0xFCA4: "COMND VSC_SendEpcLmpMessage",
    0xFCA5: "COMND VSC_TransportStatistics",
    0xFCA6: "COMND VSC_BistPostGetResults",
    0xFCAD: "COMND VSC_CurrentSensorCtrlerConfig",
    0xFCAE: "COMND VSC_Pcm2Setup",
    0xFCAF: "COMND VSC_ReadBootCrystalStatus",
    0xFCB2: "COMND VSC_SniffSubratingMaximumLocalLatency",
    0xFCB4: "COMND VSC_SET_PLC_ON_OFF",
    0xFCB5: "COMND VSC_BFC_Suspend",
    0xFCB6: "COMND VSC_BFC_Resume",
    0xFCB7: "COMND VSC_3D_TV2TV_SYNC_AND_REPORTING",
    0xFCB8: "COMND VSC_WRITE_OTP",
    0xFCB9: "COMND VSC_READ_OTP",
    0xFCBA: "COMND VSC_le_read_random_address",
    0xFCBB: "COMND VSC_le_hw_setup",
    0xFCBC: "COMND VSC_LE_DVT_TXRXTEST",
    0xFCBD: "COMND VSC_LE_DVT_TESTDATAPKT",
    0xFCBE: "COMND VSC_LE_DVT_LOG_SETUP",
    0xFCBF: "COMND VSC_LE_DVT_ERRORINJECT_SCHEME",
    0xFCC0: "COMND VSC_LE_DVT_TIMING_SCHEME",
    0xFCC1: "COMND VSC_LeScanRssiThresholdSetup",
    0xFCC2: "COMND VSC_BFCSetParameters",
    0xFCC3: "COMND VSC_BFCReadParameters",
    0xFCC4: "COMND VSC_TurnOffDynamicPowerControl",
    0xFCC5: "COMND VSC_IncreaseDecreasePowerLevel",
    0xFCC6: "COMND VSC_ReadRawRssiValue",
    0xFCC7: "COMND VSC_SetProximityTable",
    0xFCC8: "COMND VSC_SetProximityTrigger",
    0xFCCD: "COMND VSC_SET_SUB_SNIFF_INTERVAL",
    0xFCCE: "COMND VSC_ENABLE_REPEATER_FUNCTIONALITY",
    0xFCCF: "COMND VSC_UPDATE_CONFIG_ITEM",
    0xFCD0: "COMND VSC_BFCCreateConnection",
    0xFCD1: "COMND VSC_WBS_BEC_PARAMS",
    0xFCD2: "COMND VSC_ReadGoldenRange",
    0xFCD3: "COMND VSC_INITIATE_MULTICAST_BEACON_LOCK",
    0xFCD4: "COMND VSC_TERMINATE_MULTICAST",
    0xFCD7: "COMND VSC_ENABLE_H4IBSS",
    0xFCD8: "COMND VSC_BLUEBRIDGE_SPI_NEGOTIATION_REQUEST",
    0xFCD9: "COMND VSC_BLUEBRIDGE_SPI_SLEEPTHRESHOLD_REQUEST",
    0xFCDA: "COMND VSC_ACCESSORY_PROTOCOL_COMMAND_GROUP",
    0xFCDB: "COMND VSC_HandleWriteOtp_AuxData",
    0xFCDC: "COMND VSC_InitMcastIndPoll",
    0xFCDD: "COMND VSC_EnterMcastIndPoll",
    0xFCDE: "COMND VSC_DisconnectMcastIndPoll",
    0xFCE0: "COMND VSC_ExtendedInquiryHandshake",
    0xFCE1: "COMND VSC_UARTBRIDGE_ROUTE_HCI_CMD_TO_UART_BRIDGE",
    0xFCE2: "COMND VSC_Olympic",
    0xFCE4: "COMND VSC_CONFIG_HID_LHL_GPIO",
    0xFCE5: "COMND VSC_READ_HID_LHL_GPIO",
    0xFCE6: "COMND VSC_LeTxTest",
    0xFCE7: "COMND VSC_UARTBRIDGE_SET_UART_BRIDGE_PARAMETER",
    0xFCE8: "COMND VSC_BIST_BER",
    0xFCE9: "COMND VSC_HandleLeMetaVsc1",
    0xFCEA: "COMND VSC_BFC_SET_PRIORITY",
    0xFCEB: "COMND VSC_BFC_READ_PRIORITY",
    0xFCEC: "COMND VSC_ANT_COMMAND",
    0xFCED: "COMND VSC_LinkQualityStats",
    0xFCEE: "COMND VSC_READ_NATIVE_CLOCK",
    0xFCEF: "COMND VSC_BfcSetWakeupFlags",
    0xFCF2: "COMND VSC_START_DVT_TINYDRIVER",
    0xFCF4: "COMND VSC_SET_3DTV_DUAL_MODE_VIEW",
    0xFCF5: "COMND VSC_BFCReadRemoeBPCSFeatures",
    0xFCF7: "COMND VSC_IgnoreUSBReset",
    0xFCF8: "COMND VSC_SNIFF_RECONNECT_TRAIN",
    0xFCF9: "COMND VSC_AudioIPCommand",
    0xFCFA: "COMND VSC_BFCWriteScanEnable",
    0xFCFE: "COMND VSC_ReadLocalFirmwareInfo",
    0xFCFF: "COMND VSC_RSSIMeasurements",
    0xFD01: "COMND VSC_BFCReadScanEnable",
    0xFD02: "COMND VSC_EnableWbsModified",
    0xFD03: "COMND VSC_SetVsEventMask",
    0xFD04: "COMND VSC_BFCIsConnectionTBFCSuspended",
    0xFD05: "COMND VSC_SetUSBAutoResume",
    0xFD06: "COMND VSC_SetDirectionFindingParameters",
    0xFD08: "COMND VSC_ChangeLNAGainCoexECI",
    0xFD0C: "COMND VSC_LTELinkQualityMode",  # LTECoexLinkQualityMetric
    0xFD0D: "COMND VSC_LTETriggerWCI2Message",
    0xFD0E: "COMND VSC_LTEEnableWCI2Messages",
    0xFD0F: "COMND VSC_LTEEnableWCI2LoopbackTesting",
    0xFD10: "COMND VSC_ScoDiagStat",
    0xFD11: "COMND VSC_SetStreamingConnectionlessBroadcast",
    0xFD12: "COMND VSC_ReceiveStreamingConnectonlessBroadcast",
    0xFD13: "COMND VSC_WriteConnectionlessBroadcastStreamingData",
    0xFD14: "COMND VSC_FlushStreamingConnectionlessBroadcastData",
    0xFD15: "COMND VSC_FactoryCalSetTxPower",
    0xFD16: "COMND VSC_FactoryCalTrimTxPower",
    0xFD17: "COMND VSC_FactoryCalReadTempSettings",
    0xFD18: "COMND VSC_FactoryCalUpdateTableSettings",
    0xFD1A: "COMND VSC_WriteA2DPConnection",
    0xFD1B: "COMND VSC_Factory_Cal_Read_Table_Settings",
    0xFD1C: "COMND VSC_DBFW",
    0xFD1D: "COMND VSC_FactoryCalibrationRxRSSITest",
    0xFD1E: "COMND VSC_FactoryCalibrationRxRSSITest",
    0xFD1F: "COMND VSC_LTECoexTimingAdvance",
    0xFD23: "COMND VSC_HandleLeMetaVsc2",
    0xFD28: "COMND VSC_WriteLocalSupportedExtendedFeatures",
    0xFD29: "COMND VSC_PiconetClockAdjustment",
    0xFD2A: "COMND VSC_ReadRetransmissionStatus",
    0xFD2F: "COMND VSC_SetTransmitPowerRange",
    0xFD33: "COMND VSC_PageInquiryTxSuppression",
    0xFD35: "COMND VSC_RandomizeNativeClock",
    0xFD36: "COMND VSC_StoreFactoryCalibrationData",
    0xFD3B: "COMND VSC_ReadSupportedVSCs",
    0xFD3C: "COMND VSC_LEWriteLocalSupportedFeatures",
    0xFD3E: "COMND VSC_LEReadRemoteSupportedBRCMFeatures",
    0xFD40: "COMND VSC_BcsTimeline",
    0xFD41: "COMND VSC_BcsTimelineBroadcastReceive",
    0xFD42: "COMND VSC_ReadDynamicMemoryPoolStatistics",
    0xFD43: "COMND VSC_HandleIop3dtvTesterConfig",
    0xFD45: "COMND VSC_HandleAdcCapture",
    0xFD47: "COMND VSC_LEExtendedDuplicateFilter",
    0xFD48: "COMND VSC_LECreateExtendedAdvertisingInstance",
    0xFD49: "COMND VSC_LERemoveExtendedAdvertisingInstance",
    0xFD4A: "COMND VSC_LESetExtendedAdvertisingParameters",
    0xFD4B: "COMND VSC_LESetExtendedAdvertisingData",
    0xFD4C: "COMND VSC_LESetExtendedScanResponseData",
    0xFD4D: "COMND VSC_LESetExtendedAdvertisingEnable",
    0xFD4E: "COMND VSC_LEUpdateExtendedAdvertisingInstance",
    0xFD53: "COMND VSC_LEGetAndroidVendorCapabilities",
    0xFD54: "COMND VSC_LEMultiAdvtCommand",
    0xFD55: "COMND VSC_LeRPAOffload",
    0xFD56: "COMND VSC_LEBatchScanCommand",
    0xFD57: "COMND VSC_LEBrcmPCF",
    0xFD59: "COMND VSC_GetControllerActivityEnergyInfo",
    0xFD5A: "COMND VSC_ExtendedSetScanParameters",
    0xFD5B: "COMND VSC_Getdebuginfo",
    0xFD5C: "COMND VSC_WriteLocalHostState",
    0xFD6E: "COMND VSC_HandleConfigure_Sleep_Lines",
    0xFD71: "COMND VSC_SetSpecialSniffTransitionEnable",
    0xFD73: "COMND VSC_EnableBTSync",
    0xFD79: "COMND VSC_hciulp_handleBTBLEHighPowerControl",
    0xFD7C: "COMND VSC_HandleCustomerEnableHALinkCommands",
    0xFD7D: "COMND VSC_DWPTestCommands",
    0xFD7F: "COMND VSC_Olympic_LTE_Settings",
    0xFD82: "COMND VSC_WriteLERemotePublicAddress",
    0xFD86: "COMND VSC_1SecondTimerCommands",
    0xFD88: "COMND VSC_ForceWLANChannel",
    0xFD8B: "COMND VSC_SVTConfigSetup",
    0xFD8F: "COMND VSC_HandleCustomerReadHADeltaCommands",
    0xFD9A: "COMND VSC_SetupRSSCommands",
    0xFD9C: "COMND VSC_SetupRSSLocalCommands",
    0xFDA1: "COMND VSC_AudioBufferCommands",
    0xFDA4: "COMND VSC_HealthStatusReport",
    0xFDA8: "COMND VSC_ChangeConnectionPriority",
    0xFDAA: "COMND VSC_SamSetupCommand",
    0xFDAB: "COMND VSC_bthci_cmd_ble_enhancedTransmitterTest_hopping",
    0xFDAF: "COMND VSC_Handle_coex_debug_counters",
    0xFDBB: "COMND VSC_Read_Inquiry_Transmit_Power",
    0xFDBE: "COMND VSC_Enable_PADGC_Override",
    0xFDCB: "COMND VSC_WriteTxPowerAFHMode",
    0xFDCD: "COMND VSC_setMinimumNumberOfUsedChannels",
    0xFDCE: "COMND VSC_HandleBrEdrLinkQualityStats",
    0xFF5E: "COMND VSC_SectorErase",
    0xFFCE: "COMND VSC_Chip_Erase",
    0xFFED: "COMND VSC_EnterDownloadMode",
}

# def hci_cmd_parser(bytestream: bytes):
#     opcode = _read_raise_eof(bytestream, 2)
#     length = _uint8.unpack(_read_raise_eof(bytestream, 1))[0]
#     payload = bytestream.read(length)
#     return "cmd"
#
#
# def hci_event_parser(bytestream: bytes):
#     eventcode = _read_raise_eof(bytestream, 1)
#     length = _uint8.unpack(_read_raise_eof(bytestream, 1))[0]
#     payload = bytestream.read(length)
#     return "event"
#
#
# def acl_data_parser(bytestream: bytes):
#     handle_pb_bc = _read_raise_eof(bytestream, 2)
#     length = _uint16.unpack(_read_raise_eof(bytestream, 2))[0]
#     data = bytestream.read(length)
#     return "acl"
#
#
# def sco_data_parser(bytestream: bytes):
#     handle_status_rfu = _read_raise_eof(bytestream, 2)
#     length = _uint8.unpack(_read_raise_eof(bytestream, 1))[0]
#     data = bytestream.read(length)
#     return "sco"
#
#
# _PARSE_MAP = {
#     HCD_TYPES.HCI_CMD: hci_cmd_parser,
#     HCD_TYPES.ACL_DATA: acl_data_parser,
#     HCD_TYPES.SCO_DATA: sco_data_parser,
#     HCD_TYPES.HCI_EVENT: hci_event_parser,
#     HCD_TYPES.BCM_DBG: lambda x: "dbg",
# }
# _uint8 = struct.Struct("B")
# _uint16 = struct.Struct("H")
#
#
# def hcd_parser(hcd_path: str):
#     with open(hcd_path, "rb") as bytestream:
#         while True:
#             type_ = _uint8.unpack(_read_raise_eof(bytestream, 1))[0]
#             try:
#                 package = _PARSE_MAP[type_](bytestream)
#                 if package == "dbg":
#                     print("hello broadcom!")
#                     break
#                 if package is not None:
#                     yield package
#             except EOF:
#                 print("I am not doing this right!")
#                 raise EOF()
def hcd_parser(hcd_path: str):
    with open(hcd_path, "rb") as bytestream:
        while True:
            cmd = HCI_CMD(_read_raise_eof(bytestream, _hci_cmd_header_size))
            cmd.raw_payload = _read_raise_eof(bytestream, cmd.plen)
            cmd.handle_payload()
            print(cmd)


_iphone_bin_header_struct = struct.Struct(
    # "<II4x4x" "4xIIH2x" "I4x4xI" "III4x" "4xIII" "I"
    "4I"
    "3I2H"
    "4I"
    "4I"
    "4I"
    "4I"
)
_ihone_bin_header_size = _iphone_bin_header_struct.size


class IphoneBinHeader:
    def __init__(self, data: bytes):
        fields = _iphone_bin_header_struct.unpack(data)
        for i, val in enumerate(fields):
            print(f"{i}:\t0x{val:X}")
        print(data)
        print(data.hex())
        print(fields)
        # self.maybe_crc_1, _, self.maybe_rom_end, = fields[:3]
        # self.patchram_code, self.binary_offset, _, self.maybe_ram_size = fields[3:7]
        # self.move_patches, self.end_of_last_patch_source, _, = fields[7:10]
        # self.maybe_something, self.brcm_cfg, self.brcm_cfgS, _ = fields[10:14]
        #

    def __str__(self):
        return ""
        # return "\n".join(
        #     (
        #         f"Rom end: 0x{self.maybe_rom_end:X}",
        #         f"Patchram Code: 0x{self.patchram_code:X}",
        #         f"Binary Offset: 0x{self.binary_offset:X}",
        #         f"Maybe Ram size: 0x{self.maybe_ram_size:X}",
        #     )
        # )
