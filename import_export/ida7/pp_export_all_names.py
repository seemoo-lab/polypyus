from idautils import *
from idaapi import *
from idc import *
from Tkinter import *
from Tkinter import *
import Tkinter, Tkconstants, tkFileDialog
import csv

def parse_ea(ea):
    
    addr = int(ea, 16)
    if addr > max_ea or addr < min_ea:
        raise ValueError("Bad address")
    return addr


if __name__ == "__main__":       
    segfiles = {".rodata": "rodata.bin",
            ".data": "data.bin"}
    root = Tk()
    ftypes = [("CSV file", ".csv"),("Text file", ".txt"),("All files", "*")]
    root.path = tkFileDialog.asksaveasfilename(filetypes=ftypes, defaultextension = '.csv')


    with open(root.path, 'wb') as csvfile:

        pref_list = ['loc', 'sub', 'off','dword','unk','byte']
        writer = csv.writer(csvfile, delimiter=' ',
                            quotechar='|', quoting=csv.QUOTE_MINIMAL)
        for s in Segments():    
            start = idc.GetSegmentAttr(s, idc.SEGATTR_START)
            end = idc.GetSegmentAttr(s, idc.SEGATTR_END)
            while start < end:
                address = parse_ea(start)
                name = get_name(ea, gtn_flags=0)    
                print start, address, name                    
                if name.startswith(tuple(pref_list)) == False and name != "":
                    writer.writerow([name, address])  
                start = start+1
    root.destroy()