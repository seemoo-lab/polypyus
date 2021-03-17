import csv
from pathlib import Path

from loguru import logger
from polypyus.annotation_parser import CSV_KEYS_LONG
from polypyus.models import Binary
from polypyus.tools import serialize

from typing import Iterable

csv.register_dialect("space_delimiter", delimiter=" ", quoting=csv.QUOTE_MINIMAL)



def export_csv_combined(binary: Binary, path: Path):
    if binary.is_target is True:
        export_matches_csv(binary, path)
    else:
        export_annotations_csv(binary, path)


def export_matches_csv(binary: Binary, path: Path):
    logger.info(f"exporting matches for {binary.name} csv to {path}")
    stream = serialize(binary.matches, export=True)
    _export_csv_internal(stream, path)


def export_annotations_csv(binary: Binary, path: Path):
    logger.info(f"exporting annotations for {binary.name} csv to {path}")
    stream = serialize(binary.functions, export=True)
    _export_csv_internal(stream, path)


def _export_csv_internal(stream: Iterable[dict], path: Path):
    with open(path, "w") as csv_file:
        writer = csv.DictWriter(
            csv_file, fieldnames=CSV_KEYS_LONG, dialect="space_delimiter"
        )
        writer.writeheader()

        for entry in stream:
            entry["addr"] = hex(entry["addr"])
            entry["name"] = entry["name"].split(", ")[0]
            writer.writerow(
                {
                    key: value
                    for key, value in {**entry, "type": "FUNC"}.items()
                    if key in CSV_KEYS_LONG
                }
            )
