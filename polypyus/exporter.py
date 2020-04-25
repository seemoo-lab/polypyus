import csv
from pathlib import Path
from typing import Iterable

from loguru import logger
from polypyus.annotation_parser import CSV_KEYS_LONG
from polypyus.models import Binary
from polypyus.tools import serialize

csv.register_dialect("space_delimiter", delimiter=" ", quoting=csv.QUOTE_NONE)


def export_matches_csv(binary: Binary, path: Path):
    logger.info(f"exporting matches for {binary.name} csv to {path}")
    stream = serialize(binary.matches, export=True)
    with open(path, "w") as csv_file:
        writer = csv.DictWriter(
            csv_file, fieldnames=CSV_KEYS_LONG, dialect="space_delimiter"
        )
        writer.writeheader()

        for match in stream:
            match["addr"] = hex(match["addr"])
            match["name"] = match["name"].split(", ")[0]
            writer.writerow(
                {
                    key: value
                    for key, value in {**match, "type": "FUNC"}.items()
                    if key in CSV_KEYS_LONG
                }
            )
