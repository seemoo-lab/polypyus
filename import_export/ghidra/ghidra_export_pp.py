# Script to export polypus csv data

# @category Polypyus

import csv

functionManager = currentProgram.getFunctionManager()


def write_csv(csvfile, symbols):

    with open(csvfile, "w") as file:
        fieldnames = ["name", "addr", "size", "mode", "type"]
        writer = csv.DictWriter(file, delimiter=" ", fieldnames=fieldnames)

        writer.writeheader()
        for symbol in symbols:
            writer.writerow(symbol)


# https://github.com/NationalSecurityAgency/ghidra/issues/1132
def isThumbFunction(func):
    r = currentProgram.getRegister("TMode")
    value = currentProgram.programContext.getRegisterValue(r, func.entryPoint)
    return value.unsignedValueIgnoreMask == 1


def get_symbols():
    symbols = []

    funcs = functionManager.getFunctions(True)
    for func in funcs:
        symbol = {}
        symbol["name"] = func.getName()
        symbol["addr"] = hex(int(str(func.getEntryPoint()), 16))
        symbol["size"] = func.getBody().getNumAddresses()

        if isThumbFunction(func) is True:
            symbol["mode"] = "THUMB_32"
        else:
            symbol["mode"] = "ARM_32"

        symbol["type"] = "FUNC"
        symbols.append(symbol)

    return symbols


language = currentProgram.getLanguage()
if language.getProcessor == "ARM" or language.getLanguageDescription().getSize() == 32:
    csv_file = str(askFile("Choose Polypyus export CSV", "Select"))
    symbols = get_symbols()
    write_csv(csv_file, symbols)
    print("Successfully exported symbols to {}".format(csv_file))
else:
    print("PP-Ghidra only supports 32-bit ARM binaries!")
