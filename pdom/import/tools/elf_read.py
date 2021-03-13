import sys
import tempfile
from elftools.elf import elffile


class Elfloader:
    """
    Handles ELF file import including coredump symbol recovery
    """

    def __init__(self, fname, offset=0x00):
        f = open(fname, "rb")
        self.elf = elffile.ELFFile(f)
        self.offset = offset

        self.reassembled = {}

    def iter_segments(self):
        """
        Iterates over all segments. Retuns {"vaddr": vaddr, "size": size, "data": data}
        """
        for segment in self.elf.iter_segments():
            if segment.header.p_type == "PT_LOAD":
                vaddr = segment.header.p_vaddr + self.offset
                size = segment.header.p_memsz
                data = segment.data()
                yield {"vaddr": vaddr, "size": size, "data": data}

    def iter_symbols(self):
        """
        Iterates over all symbols in ELF or Core files
        """
        for section in self.elf.iter_sections():
            if section.header.sh_type in ["SHT_SYMTAB", "SHT_DYNSYM"]:
                for symbol in section.iter_symbols():
                    name = symbol.name
                    entry = symbol.entry
                    value = symbol.entry["st_value"] + self.offset
                    typ = symbol.entry["st_info"][
                        "type"
                    ]  # STT_NOTYPE STT_FUNC STT_FILE

                    if name != "" and "$" not in name:
                        yield {
                            "name": name,
                            "value": value,
                            "type": typ,
                            "entry": entry,
                        }

            #  Find ELF files in core file
            if section.header.sh_type in ["SHT_NOTE"]:
                for note in section.iter_notes():
                    if note.n_type == "NT_FILE":
                        print("Found NT_FILE")
                        for fname, desc in zip(
                            note["n_desc"]["filename"],
                            note["n_desc"]["Elf_Nt_File_Entry"],
                        ):
                            if fname[:9] == b"/dev/zero":
                                continue
                            print(fname, desc)
                            # segment = self.get_segment(desc["vm_start"])
                            # data = segment.data()[:segment.header["p_filesz"]]
                            # self.reassemble_elf(fname, data,  desc["vm_start"])
                            if desc["page_offset"]:
                                try:
                                    e = Elfloader(fname, desc["vm_start"])
                                    for x in e.iter_symbols():
                                        yield x
                                except:
                                    pass

        for x in self.iter_symbols_reassembled():
            yield x

    """
		Not working yet
		"""

    def iter_symbols_reassembled(self):
        print(self.reassembled)
        for fname in self.reassembled.keys():
            (tmp, vaddr) = self.reassembled[fname]
            tmp.file.seek(0)
            print(fname)
            if tmp.file.read(4) == b"\x7fELF":
                print("Found ELF file %s" % fname)
                print(tmp.name)
                tmp.file.close()
                try:
                    e = Elfloader(tmp.name, vaddr)
                    for x in e.iter_symbols():
                        yield x
                except:
                    print("fail")
                    import traceback

                    traceback.print_exc()
                input()

    """
		Not working yet
	"""

    def reassemble_elf(self, fname, data, vaddr):
        """
        Reassembles ELF files from pages in core dump
        """
        if fname not in self.reassembled:
            tmp = tempfile.NamedTemporaryFile()
            tmp.file.write(data)
            self.reassembled[fname] = (tmp, vaddr)

        else:
            (tmp, vaddr) = self.reassembled[fname]
            tmp.file.write(data)
            self.reassembled[fname] = (tmp, vaddr)

    def get_segment(self, addr):
        """
        Get a segment data by address
        """
        for segment in self.elf.iter_segments():
            if segment.header.p_type == "PT_LOAD":
                vaddr = segment.header.p_vaddr + self.offset
                if vaddr == addr:
                    return segment

    def get_all_symbols(self):
        """
        Get a list of all symbols
        """
        symbolList = []
        for i in self.iter_symbols():
            symbol_name = i.get("name")
            symbol_addr = i.get("value")
            symbol_size = i.get("entry").get("st_size")
            symbol_type = i.get("type").replace("STT_", "")
            symbolList.append(
                {
                    "name": symbol_name,
                    "addr": symbol_addr,
                    "size": symbol_size,
                    "type": symbol_type,
                }
            )

        return symbolList

    def get_all_segments(self):
        """
        Get a list of all segments with type equals PT_LOAD
        """
        segmentsList = []
        for segment in self.elf.iter_segments():
            if segment.header.p_type == "PT_LOAD":

                name = ""
                for section in self.elf.iter_sections():
                    if segment.header.get("p_paddr") == section.header.get("sh_addr"):
                        name = section.name

                Start = segment.header.get("p_vaddr")
                offfset = segment.header.get("p_offset")
                size = segment.header.get("p_memsz")
                R = (segment.header.get("p_flags") >> 2) & 1
                W = (segment.header.get("p_flags") >> 1) & 1
                E = (segment.header.get("p_flags") >> 0) & 1
                Align = segment.header.get("p_align")
                segmentsList.append(
                    {
                        "name": name,
                        "start": Start,
                        "end": (Start + size),
                        "R": R,
                        "W": W,
                        "X": E,
                        "D": 0,
                        "L": 0,
                        "align": Align,
                        "base": 00,
                        "type": "",
                        "class": "",
                        "ad": 32,
                        "T": 00,
                        "DS": 00,
                    }
                )

        return segmentsList

    def get_all_sections(self):
        """
        Get a list of all sections mapped with attributes from the segment, the section is in
        """
        # get all sections
        sectionMap = {}
        for i in self.elf.iter_sections():
            sectionMap[i.header.get("sh_addr")] = i

        # get all segments with all attributes
        segmentsMap = {}
        for segment in self.elf.iter_segments():
            if segment.header.p_type == "PT_LOAD":
                start = segment.header.get("p_vaddr")
                offfset = segment.header.get("p_offset")
                size = segment.header.get("p_memsz")
                R = (segment.header.get("p_flags") >> 2) & 1
                W = (segment.header.get("p_flags") >> 1) & 1
                E = (segment.header.get("p_flags") >> 0) & 1
                Align = segment.header.get("p_align")
                segmentsMap[start] = {
                    "start": start,
                    "end": (start + size),
                    "R": R,
                    "W": W,
                    "X": E,
                    "D": 0,
                    "L": 0,
                    "align": Align,
                    "base": 00,
                    "type": "",
                    "class": "",
                    "ad": 32,
                    "T": 00,
                    "DS": 00,
                    "sections": [],
                }

        # map all sections in segments
        for i in sectionMap:
            for j in segmentsMap:
                if segmentsMap[j].get("start") <= i <= segmentsMap[j].get("end"):
                    segmentsMap[j].get("sections").append(sectionMap[i])

        # create new list of sections with attributes from segments
        finalList = []
        for i in segmentsMap:
            for j in segmentsMap[i].get("sections"):
                finalList.append(
                    {
                        "name": j.name,
                        "start": hex(j.header.get("sh_addr")),
                        "end": "0xFFFFFFFF",
                        "R": segmentsMap[i].get("R"),
                        "W": segmentsMap[i].get("W"),
                        "X": segmentsMap[i].get("X"),
                        "D": 0,
                        "L": 0,
                        "align": segmentsMap[i].get("align"),
                        "base": 00,
                        "type": "",
                        "class": "",
                        "ad": 32,
                        "T": 00,
                        "DS": 00,
                    }
                )

        return finalList
