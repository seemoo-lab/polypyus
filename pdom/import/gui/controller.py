import os
import time
import csv

from tools.elf_read import Elfloader
from tools.compare_symbols import SignatureBuilder
from tools.ida_tools import IDAtools
from tools.parse_hardwareregister import ParseHardwareregisterFile

from sqlite_reader.sql_querries import SqlController
from sqlite_reader.read_db import ReadDatabase
from sqlite_reader.symbol_builder import SymbolBuilder


class Controller:
    def import_file(
        gui_Object,
        filePath,
        import_functions,
        import_objects,
        import_sections,
        overwrite_names,
        offset,
    ):
        progressCounter = 0

        if filePath.endswith(".elf"):  # elf file
            elfReader = Elfloader(filePath)

            if import_sections:
                for sections in elfReader.get_all_sections():
                    IDAtools.create_segement(sections, offset)

            listSymbols = elfReader.get_all_symbols()
            for symbol in listSymbols:
                gui_Object.set_progress(int(progressCounter / len(listSymbols) * 100))
                progressCounter = progressCounter + 1
                Controller.create_function_data(
                    symbol,
                    overwrite_names,
                    offset,
                    "FUNC",
                    "OBJECT",
                    import_functions,
                    import_objects,
                )

        else:  # Polypyus csv export
            fileLines = open(filePath, "r").readlines()
            fileLines = [x.strip() for x in fileLines]

            for i in fileLines:
                gui_Object.set_progress(int(progressCounter / len(fileLines) * 100))
                progressCounter = progressCounter + 1

                line = i.split(" ")
                line = list(filter(None, line))
                try:
                    symbol = {
                        "name": line[0],
                        "addr": str(int(line[1], 16)),
                        "size": line[2],
                        "type": line[4],
                    }
                except (IndexError, ValueError):
                    continue
                Controller.create_function_data(
                    symbol,
                    overwrite_names,
                    offset,
                    "FUNC",
                    "OBJECT",
                    import_functions,
                    import_objects,
                )

    def import_userdefined_csv(
        gui_Object,
        filePath,
        import_functions,
        import_objects,
        overwrite_names,
        offset,
        delimiter,
        identFunc,
        identData,
        nameCol,
        addrCol,
        typeCol,
        sizeCol,
    ):
        progressCounter = 0

        fileLines = open(filePath, "r").readlines()
        fileLines = [x.strip() for x in fileLines]

        for i in fileLines:
            gui_Object.set_progress(int(progressCounter / len(fileLines) * 100))
            progressCounter = progressCounter + 1

            line = i.split(delimiter)
            line = list(filter(None, line))
            try:
                symbol = {
                    "name": line[int(nameCol)],
                    "addr": str(int(line[int(addrCol)], 16)),
                    "size": line[int(sizeCol)],
                    "type": line[int(typeCol)],
                }
            except (IndexError, ValueError):
                continue

            Controller.create_function_data(
                symbol,
                overwrite_names,
                offset,
                identFunc,
                identData,
                import_functions,
                import_objects,
            )

    def create_function_data(
        symbol,
        overwrite_names,
        offset,
        identFunc,
        identData,
        import_functions,
        import_objects,
    ):
        typeSymbol = symbol.get("type")
        if (typeSymbol == identFunc) and import_functions:
            IDAtools.create_function(symbol, overwrite_names, offset)
        elif (typeSymbol == identData) and import_objects:
            IDAtools.create_object(symbol, overwrite_names, offset)

    ######################################################################## Signature import ###############################################################################

    def import_database(gui_Object, referenceFilePath, additionalPathList):
        csvFiles = []  # save produced csv files
        referencePDOM = referenceFilePath.split("/")[-1]
        additionalPathList.append(referenceFilePath)
        pathMap = {}  # save path of the database of each used pdom

        progress_counter = 1
        symbol_builder = SymbolBuilder(True)

        # search in each database for possible signatures
        for database_path in additionalPathList:
            gui_Object.set_state(
                "Build CSV "
                + str(progress_counter)
                + "/"
                + str(len(additionalPathList))
            )
            progress_counter = progress_counter + 1

            currentPath = os.getcwd()
            try:
                os.mkdir(currentPath + "/comparedDatabases")
            except:
                pass
            csvFolder = currentPath + "/comparedDatabases/"
            created_csv_path = (
                csvFolder
                + database_path.split("/")[-1]
                + "."
                + str(time.time())
                + ".csv"
            )

            Controller = SqlController(database_path)

            # search for signatures and produce csv:
            listOfFunctioNames = IDAtools.get_names()
            ReadDatabase.import_symbols_from_list(
                Controller, gui_Object, listOfFunctioNames, symbol_builder
            )
            symbol_builder.write_csv(created_csv_path, database_path.split("/")[-1])

            # clear searched symbols for next database
            IDAtools.clean_dict()
            symbol_builder.clean_csvLines()

            csvFiles.append(created_csv_path)
            pathMap[database_path.split("/")[-1]] = database_path

        # create final signature file
        finalSignaturesCSVPath = SignatureBuilder.get_final_signature_csv(
            csvFiles, referencePDOM, csvFolder
        )
        listImportSig = list(
            csv.reader(open(finalSignaturesCSVPath, "r"), delimiter=";")
        )

        # import final signatures
        symbol_builder.set_writeCSV(False)
        controllerMap = {}
        progressCounter = 0
        for (
            line
        ) in (
            listImportSig
        ):  # [symbolName, signature, databasePDOM1, databasePDOM2, ....]
            gui_Object.set_progress(int(progressCounter / len(listImportSig) * 100))
            progressCounter = progressCounter + 1
            gui_Object.set_state("Import best signatures")

            symbol = line[0]
            signature = line[1]
            for pdoms in line[2:]:
                if not pdoms in controllerMap:
                    controllerMap[pdoms] = SqlController(pathMap[pdoms])

                Controller = controllerMap[pdoms]
                ReadDatabase.import_symbols_from_list(
                    Controller, gui_Object, [symbol], symbol_builder
                )

            IDAtools.set_function_type(symbol, signature, True)

    ######################################################################## hardware register import ###############################################################################

    def import_hardware_regs(overwrite_names, Path, import_segments):

        segements = ParseHardwareregisterFile.get_segments(Path)
        register = ParseHardwareregisterFile.get_register(Path)

        if import_segments:
            for seg in segements:
                IDAtools.create_segement(seg, 0)

        for regs in register:
            IDAtools.create_object(regs, overwrite_names, 0)
            # IDAtools.set_global_data(regs.get("name"), regs.get("type"))
