from csv_symbols_io import read_symbols_csv
from tools import import_functions
import idaapi
import ida_auto


if __name__ == "__main__":
    csv_file = idaapi.ask_file(0, "*.csv", "Select symbol csv")
    fncs, _ = read_symbols_csv(csv_file)
    import_functions(fncs, always_thumb=False)
