import csv
from tools import parse_ea, ea_to_hex
import idautils
import idc


EXPORT_FIELDS = ["name", "addr", "size", "type", "mode"]


def write_func_csv(target):

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


exportPath = ""
write_func_csv(exportPath)
