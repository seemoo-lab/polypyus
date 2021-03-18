# Script to import polypus csv data

# @category Polypyus

import csv

from ghidra.app.cmd.disassemble import ArmDisassembleCommand

OVERWRITE_EXISTING = False


functionManager = currentProgram.getFunctionManager()
addr_factory = currentProgram.getAddressFactory()


def read_csv(csv_file):
    """
    Returns a dict with the polypypus data
    """
    symbols = []
    with open(csv_file, "r") as file:
        fieldnames = ["name", "addr", "size", "mode", "type"]
        reader = csv.DictReader(file, delimiter=" ", fieldnames=fieldnames)

        for row in reader:
            symbols.append(row)

    return symbols


def create_function_from_pp(symbol):
    """
    Takes
    """
    name = symbol["name"]
    size = symbol["size"]
    mode = symbol["mode"]

    start = toAddr(int(symbol["addr"], 16))
    end = toAddr(int(symbol["addr"], 16) + int(symbol["size"]))

    func = functionManager.getFunctionAt(start)

    if func is not None:
        if OVERWRITE_EXISTING is True:
            removeFunction(func)
        else:
            return False

    func = createFunction(start, name)
    if func is None:
        return False

    addr_set = addr_factory.getAddressSet(start, end)
    func.body.add(addr_set)
    is_thumb = True if mode == "THUMB_32" else False

    disas = ArmDisassembleCommand(start, addr_set, is_thumb)
    disas.enableCodeAnalysis(False)
    disas.applyTo(currentProgram)

    return True


def apply_symbols(symbols):
    for symbol in symbols:
        if symbol["type"] == "FUNC":
            if create_function_from_pp(symbol) is True:
                print("{}: Successfully created function".format(symbol["name"]))
            else:
                print("{}: Function generation failed".format(symbol["name"]))

        else:
            print("{}: type {} not supported".format(symbol["name"], symbol["type"]))


language = currentProgram.getLanguage()
if language.getProcessor == "ARM" or language.getLanguageDescription().getSize() == 32:
    csv_file = str(askFile("Choose Polypyus CSV", "Select"))
    symbols = read_csv(csv_file)
    apply_symbols(symbols)
else:
    print("PP-Ghidra only supports 32-bit ARM binaries!")
