import csv
import operator
from tools import parse_ea, ea_to_hex

import idautils, idc

BASIC_FIELDNAMES = ["name", "addr", "type", "size"]


def modifi_csv(dict):
    symbols = []
    for index, row in enumerate(dict):
        symbols.append(row)
        tempList = list(row)
        if row[0][:1].isdigit():
            tempList[0] = "_" + tempList[0]
            symbols[index] = tempList

    for index, row in enumerate(symbols):                       
        if len(symbols)-1 > index and symbols[index][0] == symbols[index+1][0]:
            k = 1
            while symbols[index][0] == symbols[index+k][0]:
                templst = list(symbols[index+k])
                templst[0] =  templst[0] +  "_" + str(k)
                symbols[index+k] = templst
                k = k+1

    return symbols

def sort_csv(file_path):
    symbols = []
    with open(file_path, "r") as f:
        reader = csv.reader(f, delimiter=" ")
        sortedlist = sorted(reader, key=operator.itemgetter(0)) 
        for line in sortedlist:
        	symbols.append(line)
       
    return symbols


def read_symbols_csv(file_path):
    """opens csv and returns list of symbols
    
    Arguments:
        file_path {str} -- filepath of csv
    """

    fncs = []
    objs = []
    reader = sort_csv(file_path)
    for row in reader:
        try:
            size = int(row[2])
            addr = parse_ea(row[1])
        except ValueError as e:
            print(e, row)
            continue
        name = row[0].replace("~", "_")
        if row[4] == "FUNC":
            thumb = False
            if addr % 2 == 1:
                thumb = True
                addr -= 1
            thumb = thumb or row[3] == "THUMB_32"
            fncs.append((name, size, addr, thumb))
        elif row[4] == "OBJECT":
            objs.append((name, size, addr, None))
        else:
            print("Ignoring", row)
    return modifi_csv(fncs),modifi_csv(objs)


EXPORT_FIELDS = ["name", "addr", "size", "type", "mode"]
def write_func_csv(target):
    """reads functions from current idb and writes them to a csv
    
    Arguments:
        target {str} -- path of the file to write to.
    """
    with open(target, "w") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=EXPORT_FIELDS, delimiter=" ")
        writer.writeheader()
        f_ea = idautils.Functions()
        for ea in f_ea:
            data = dict(
                name=idc.get_func_name(ea),
                addr=ea_to_hex(ea),
                size=idc.get_func_attr(ea, idc.FUNCATTR_END) - ea,
                type="FUNC",
                mode="THUMB_32",
            )
            writer.writerow(data)
    print("functions exported to " + target)

def write_sample_csv(target, sample):
    with open(target, "w") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=EXPORT_FIELDS, delimiter=" ")
        writer.writeheader()
        for name, size, addr, thumb in sample:
            data = dict(
                name=name,
                addr=ea_to_hex(addr),
                size=size,
                type="FUNC",
                mode="THUMB_32" if thumb else "",
            )
            writer.writerow(data)
    print("sample exported to " + target)

