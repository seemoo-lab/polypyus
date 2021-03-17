import csv

from .read_db_c import CReader
from .read_db_cpp import CppReader


class ReadDatabase:
    def import_symbols_from_list(
        sql_controller, gui_Object, symbol_name_list, symbol_builder, full_search=False
    ):

        c_reader = CReader(sql_controller, symbol_builder)
        cpp_reader = CppReader(sql_controller, symbol_builder)

        progressCounter = 0
        for lines in symbol_name_list:
            progressCounter = progressCounter + 1

            if len(symbol_name_list) > 2:
                gui_Object.set_progress(
                    int(progressCounter / len(symbol_name_list) * 100)
                )

            if lines != "":
                result = sql_controller.get_entry_by_name("PDOMCPPFunction", lines)
                if result:
                    cpp_reader.read_cpp_function(result)
                    continue

                result = sql_controller.get_entry_by_name("PDOMCPPMethod", lines)
                if result:
                    cpp_reader.read_cpp_method(result)
                    continue

                result = sql_controller.get_entry_by_name("PDOMCFunction", lines)
                if result:
                    c_reader.read_c_function(result)
                    continue

                result = sql_controller.get_entry_by_name(
                    "PDOMCPPMethodSpecialization", lines
                )
                if result:
                    cpp_reader.read_cpp_method_specialization(result)
                    continue

                result = sql_controller.get_entry_by_name("PDOMCPPConstructor", lines)
                if result:
                    cpp_reader.read_cpp_constructor(result)
                    continue

                result = sql_controller.get_entry_by_name(
                    "PDOMCPPConstructorTemplate", lines
                )
                if result:
                    cpp_reader.read_cpp_constructor_template(result)
                    continue

                result = sql_controller.get_entry_by_name(
                    "PDOMCPPFunctionInstance", lines
                )
                if result:
                    cpp_reader.read_cpp_function_instance(result)
                    continue

                result = sql_controller.get_entry_by_name(
                    "PDOMCPPFunctionTemplate", lines
                )
                if result:
                    cpp_reader.read_cpp_function_template(result)
                    continue

                result = sql_controller.get_entry_by_name(
                    "PDOMCPPMethodInstance", lines
                )
                if result:
                    cpp_reader.read_cpp_method_instance(result)
                    continue

                result = sql_controller.get_entry_by_name(
                    "PDOMCPPMethodTemplate", lines
                )
                if result:
                    cpp_reader.read_cpp_method_template(result)
                    continue

                result = sql_controller.get_entry_by_name(
                    "PDOMCPPMethodTemplateSpecialization", lines
                )
                if result:
                    cpp_reader.read_cpp_method_template_specialization(result)
                    continue

                if not full_search:
                    continue

                ############################ search only for functions, not for types ##################

                result = sql_controller.get_entry_by_name("PDOMCStructure", lines)
                if result:
                    c_reader.read_c_structure(result)
                    continue

                result = sql_controller.get_entry_by_name("PDOMCTypedef", lines)
                if result:
                    c_reader.read_c_typedef(result)
                    continue

                result = sql_controller.get_entry_by_name("PDOMCPPVariable", lines)
                if result:
                    c_reader.read_c_variable(result)
                    continue

                result = sql_controller.get_entry_by_name("PDOMCPPAliasTemplate", lines)
                if result:
                    cpp_reader.read_cpp_alias_template(result)
                    continue

                result = sql_controller.get_entry_by_name("PDOMCPPClassInstance", lines)
                if result:
                    cpp_reader.read_cpp_class_instance(result)
                    continue

                result = sql_controller.get_entry_by_name(
                    "PDOMCPPClassSpecialization", lines
                )
                if result:
                    cpp_reader.read_cpp_class_specialization(result)
                    continue

                result = sql_controller.get_entry_by_name("PDOMCPPClassTemplate", lines)
                if result:
                    cpp_reader.read_cpp_class_template(result)
                    continue

                result = sql_controller.get_entry_by_name(
                    "PDOMCPPClassTemplatePartialSpecialization", lines
                )
                if result:
                    cpp_reader.read_cpp_class_template_partial_specialization(result)
                    continue

                result = sql_controller.get_entry_by_name("PDOMCPPClassType", lines)
                if result:
                    cpp_reader.read_cpp_class_type(result)
                    continue

                result = sql_controller.get_entry_by_name("PDOMCPPTypedef", lines)
                if result:
                    cpp_reader.read_cpp_typedef(result)
                    continue

                result = sql_controller.get_entry_by_name(
                    "PDOMCPPTypedefSpecialization", lines
                )
                if result:
                    cpp_reader.read_cpp_typedef_specialization(result)
                    continue

                result = sql_controller.get_entry_by_name("PDOMCPPVariable", lines)
                if result:
                    cpp_reader.read_cpp_variable(result)
                    continue
