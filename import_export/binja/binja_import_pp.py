#!/usr/bin/env python
#
# Copyright (c) 2015-2017 Vector 35 LLC
# Extended June 2020 by jiska for Polypyus CSVs
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import csv
from argparse import ArgumentParser, FileType

from binaryninja.binaryview import BinaryViewType
from binaryninja.types import (Type, Symbol)
from binaryninja.enums import (SymbolType, IntegerDisplayType, InstructionTextTokenType)
from binaryninja.plugin import PluginCommand
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.interaction import (ChoiceField, OpenFileNameField, get_form_input)
from binaryninja.log import log_error


def log(message):
    if task is None:
        print(message)
    else:
        task.progress = message


def import_pp(csv_file, bv, options):
    if csv_file is None:
        return False, "No csv file specified"

    resolved_functions = []
    try:
        resolved_functions = read_symbols_csv(csv_file)
    except Exception as e:
        return False, "Failed to parse csv file {} {}".format(csv_file, e)

    # import functions
    log("Applying import data...")
    for fun in resolved_functions:
        bv.add_function(fun["start"])
        func = bv.get_function_at(fun["start"])
        # TODO only filters for sub_, should also filter for nonsense function start matcher names
        if fun["name"] != ("sub_%x" % fun["start"]):   # this script already filters for "sub_"
            func.name = fun["name"]

    log("Updating analysis...")
    bv.update_analysis_and_wait()
    return True, None


def read_symbols_csv(file_path):
    """opens csv and returns list of symbols

    Arguments:
        file_path {str} -- filepath of csv

    FIXME partially dupliate code with csv_symbols_io.csv?
    """

    functions = []
    with open(file_path, "r") as f:
        reader = csv.reader(f, delimiter=" ")
        next(reader)  # skip header
        for line in reader:

            # TODO forcing THUMB mode here
            # subtract 1 if odd
            addr = int(line[1], 16)
            if addr % 2:
                addr -= 1

            data = dict(
                name=line[0],
                start=addr,
            )
            functions.append(data)

    return functions


class GetOptions:
    def __init__(self, interactive=False):
        if interactive:
            csv_file = OpenFileNameField("Import csv file")
            get_form_input([csv_file], "Polypyus Import Options")
            self.verbose = True
            if csv_file.result == '':
                self.csv_file = None
            else:
                self.csv_file = csv_file.result
            self.output_name = None
        return

        # headless
        descr = "Export functions from a Polypyus csv into an existing Binary Ninja database."
        parser = ArgumentParser(description=descr)
        parser.add_argument('csv', type=FileType('w'), help="Path to Polypyus csv.")
        parser.add_argument('bndb', type=FileType('r'), help="Path to Binary Ninja database.")
        args  = parser.parse_args()
        self.csv_file = args.csv
        self.input_file = args.csv
        self.output_name = args.bndb


def main():
    options = GetOptions()

    log("Loading the binary: {}".format(options.input_file))

    bv = BinaryViewType.get_view_of_file(options.input_file)
    if bv is None:
        print("Could not open {}".format(options.input_file))
        return False

    (success, error_message) = import_pp(options.csv_file, bv, options.output_name, options)
    if not success:
        print("Error:", error_message)
        return

    log("Writing out {}".format(options.output_name))
    bv.create_database(options.output_name)
    return


class ImportPPInBackground(BackgroundTaskThread):
    def __init__(self, bv, options):
        global task
        BackgroundTaskThread.__init__(self, "Importing data from Polypyus", False)
        self.csv_file = options.csv_file
        self.options = options
        self.bv = bv
        task = self

    def run(self):
        (success, error_message) = import_pp(self.options.csv_file, self.bv, self.options)
        if not success:
            log_error(error_message)


def import_pp_in_background(bv):
    options = GetOptions(True)
    background_task = ImportPPInBackground(bv, options)
    background_task.start()


if __name__ == "__main__":
    main()
else:
    PluginCommand.register("Import data from Polypyus", "Import data from Polypyus", import_pp_in_background)
