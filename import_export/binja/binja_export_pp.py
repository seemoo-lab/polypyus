#!/usr/bin/env python
#
# Copyright (c) 2018 zznop
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
from binaryninja import *


def get_functions(bv):
    """Populate dictionary of function names and offsets"""
    functions = []
    for func in bv.functions:

        # rewrite mode to polypyus representation
        mode = func.arch.name
        if mode == "thumb2":
            mode = "THUMB_32"

        # create dict for csv
        # format:
        #  name, 0xaddr, size, type, mode
        data = dict(
            name=func.name,
            addr="{0:#x}".format(func.start),
            size=func.total_bytes,
            type="FUNC",
            mode=mode,
        )
        functions.append(data)

    return functions


def export_bn(csv_file, bv):
    """Construct csv array of everything we want to export"""
    export_fields = ["name", "addr", "size", "type", "mode"]
    csv_array = get_functions(bv)

    try:
        with open(csv_file, "w") as f:
            writer = csv.DictWriter(f, fieldnames=export_fields, delimiter=" ")
            writer.writeheader()
            for row in csv_array:
                writer.writerow(row)
    except Exception as ex:
        return False, "Failed to create csv file {} {}".format(csv_file, ex)

    return True, None


class GetOptions:
    def __init__(self, interactive=False):
        # from BN UI
        if interactive:
            csv_file = OpenFileNameField("Export functions to Polypyus csv file")
            get_form_input([csv_file], "BN Export Options")
            if csv_file.result == "":
                self.csv_file = None
            else:
                self.csv_file = csv_file.result
            return

        # headless
        descr = "Export functions from existing Binary Ninja database to Polypyus csv format."
        parser = ArgumentParser(description=descr)
        parser.add_argument(
            "bndb", type=FileType("r"), help="Path to Binary Ninja database."
        )
        parser.add_argument("csv", type=FileType("w"), help="Path to Polypyus csv.")
        args = parser.parse_args()
        self.bn_database = args.bndb
        self.csv_file = args.csv


class ExportBNInBackground(BackgroundTaskThread):
    def __init__(self, bv, options):
        global task
        BackgroundTaskThread.__init__(self, "Exporting Polypyus from BN", False)
        self.csv_file = options.csv_file
        self.options = options
        self.bv = bv
        task = self

    def run(self):
        (success, error_message) = export_bn(self.options.csv_file, self.bv)
        if not success:
            log_error(error_message)


def export_bn_headless():
    """Export data running as headless script"""
    options = GetOptions(False)
    bv = BinaryViewType.get_view_of_file(options.bn_database)
    bv.update_analysis_and_wait()
    (success, error_message) = export_bn(options.csv_file, bv)
    if not success:
        print("Error: {}".format(error_message))


def export_bn_in_background(bv):
    """Export data in background from BN UI"""
    options = GetOptions(True)
    background_task = ExportBNInBackground(bv, options)
    background_task.start()


if __name__ == "__main__":
    export_bn_headless()
else:
    PluginCommand.register(
        "Export Polypyus from BN", "Export Polypyus from BN", export_bn_in_background
    )
