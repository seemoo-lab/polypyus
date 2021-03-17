from tools.ida_tools import IDAtools


class CReader:
    sql_controller = None
    symbol_builder = None

    def __init__(self, SQLcon, symbol_builder_):
        self.sql_controller = SQLcon
        self.symbol_builder = symbol_builder_

    def call_c_function_by_owner(self, table, ownerID, ownerVar):

        if table == "CArrayType":
            return self.read_c_array_type(
                self.sql_controller.get_entry_by_owner_id(
                    "CArrayType", ownerID, ownerVar
                )
            )
        if table == "CBasicType":
            return self.read_c_basic_type(
                self.sql_controller.get_entry_by_owner_id(
                    "CBasicType", ownerID, ownerVar
                )
            )
        if table == "CFunctionType":
            return self.read_c_function_type(
                self.sql_controller.get_entry_by_owner_id(
                    "CFunctionType", ownerID, ownerVar
                )
            )
        if table == "CPointerType":
            return self.read_c_pointer_type(
                self.sql_controller.get_entry_by_owner_id(
                    "CPointerType", ownerID, ownerVar
                )
            )
        if table == "CQualifierType":
            return self.read_c_qualifier_type(
                self.sql_controller.get_entry_by_owner_id(
                    "CQualifierType", ownerID, ownerVar
                )
            )
        if table == "PDOMCEnumeration":
            return self.read_c_enumeration(
                self.sql_controller.get_entry_by_owner_id(
                    "PDOMCEnumeration", ownerID, ownerVar
                )
            )
        if table == "PDOMCEnumerator":
            return self.read_c_enumerator(
                self.sql_controller.get_entry_by_owner_id(
                    "PDOMCEnumerator", ownerID, ownerVar
                )
            )
        if table == "PDOMCField":
            return self.read_c_field(
                self.sql_controller.get_entry_by_owner_id(
                    "PDOMCField", ownerID, ownerVar
                )
            )
        if table == "PDOMCFunction":
            return self.read_c_function(
                self.sql_controller.get_entry_by_owner_id(
                    "PDOMCFunction", ownerID, ownerVar
                )
            )
        if table == "PDOMCParameter":
            return self.read_c_parameter(
                self.sql_controller.get_entry_by_owner_id(
                    "PDOMCParameter", ownerID, ownerVar
                )
            )
        if table == "PDOMCStructure":
            return self.read_c_structure(
                self.sql_controller.get_entry_by_owner_id(
                    "PDOMCStructure", ownerID, ownerVar
                )
            )
        if table == "PDOMCTypedef":
            return self.read_c_typedef(
                self.sql_controller.get_entry_by_owner_id(
                    "PDOMCTypedef", ownerID, ownerVar
                )
            )
        if table == "PDOMCVariable":
            return self.read_c_variable(
                self.sql_controller.get_entry_by_owner_id(
                    "PDOMCVariable", ownerID, ownerVar
                )
            )

    def call_c_function_by_id(self, table, ID):

        if table == "CArrayType":
            return self.read_c_array_type(
                self.sql_controller.get_entry_by_id("CArrayType", ID)
            )
        if table == "CBasicType":
            return self.read_c_basic_type(
                self.sql_controller.get_entry_by_id("CBasicType", ID)
            )
        if table == "CFunctionType":
            return self.read_c_function_type(
                self.sql_controller.get_entry_by_id("CFunctionType", ID)
            )
        if table == "CPointerType":
            return self.read_c_pointer_type(
                self.sql_controller.get_entry_by_id("CPointerType", ID)
            )
        if table == "CQualifierType":
            return self.read_c_qualifier_type(
                self.sql_controller.get_entry_by_id("CQualifierType", ID)
            )
        if table == "PDOMCEnumeration":
            return self.read_c_enumeration(
                self.sql_controller.get_entry_by_id("PDOMCEnumeration", ID)
            )
        if table == "PDOMCEnumerator":
            return self.read_c_enumerator(
                self.sql_controller.get_entry_by_id("PDOMCEnumerator", ID)
            )
        if table == "PDOMCField":
            return self.read_c_field(
                self.sql_controller.get_entry_by_id("PDOMCField", ID)
            )
        if table == "PDOMCFunction":
            return self.read_c_function(
                self.sql_controller.get_entry_by_id("PDOMCFunction", ID)
            )
        if table == "PDOMCParameter":
            return self.read_c_parameter(
                self.sql_controller.get_entry_by_id("PDOMCParameter", ID)
            )
        if table == "PDOMCStructure":
            return self.read_c_structure(
                self.sql_controller.get_entry_by_id("PDOMCStructure", ID)
            )
        if table == "PDOMCTypedef":
            return self.read_c_typedef(
                self.sql_controller.get_entry_by_id("PDOMCTypedef", ID)
            )
        if table == "PDOMCVariable":
            return self.read_c_variable(
                self.sql_controller.get_entry_by_id("PDOMCVariable", ID)
            )

    def get_array_list(self, table, ID, var):
        parameterList = self.sql_controller.get_entry_by_owner_id_array(
            str(table), ID, var
        )
        parameter = []
        if isinstance(parameterList, list):
            for entries in parameterList:
                ArrayPos = 0
                if table != "BTreeIndex":
                    ArrayPos = entries.get("ArrayPos")
                if entries.get("TableRefSubId") == 0:
                    parameter.append(
                        [
                            ArrayPos,
                            self.call_c_function_by_owner(
                                entries.get("TableRef"),
                                entries.get("ID"),
                                entries.get("OwnerVariable"),
                            ),
                        ]
                    )
                else:
                    parameter.append(
                        [
                            ArrayPos,
                            self.call_c_function_by_id(
                                entries.get("TableRef"), entries.get("TableRefSubId")
                            ),
                        ]
                    )
            return parameter
        else:
            ArrayPos = 0
            if table != "BTreeIndex":
                ArrayPos = parameterList.get("ArrayPos")
            if parameterList.get("TableRefSubId") == 0:
                return [
                    [
                        ArrayPos,
                        self.call_c_function_by_owner(
                            parameterList.get("TableRef"),
                            parameterList.get("ID"),
                            parameterList.get("OwnerVariable"),
                        ),
                    ]
                ]
            else:
                return [
                    [
                        ArrayPos,
                        self.call_c_function_by_id(
                            parameterList.get("TableRef"),
                            parameterList.get("TableRefSubId"),
                        ),
                    ]
                ]

    def read_c_array_type(self, line):

        size = line.get("size")
        if not size:
            size = 0

        if line.get("TypeTableSubId") == 0:
            return {
                "table": "ArrayType",
                "size": size,
                "type": self.call_c_function_by_owner(
                    line.get("TypeTable"), line.get("ID"), "type"
                ),
            }
        else:
            return {
                "table": "ArrayType",
                "size": size,
                "type": self.call_c_function_by_id(
                    line.get("TypeTable"), line.get("TypeTableSubId")
                ),
            }

    def read_c_basic_type(self, line):
        return {"table": "BasicType", "name": line.get("Name")}

    def read_c_function_type(self, line):
        if line.get("ReturnTypeTableSubId") == 0:
            ReturnType = self.call_c_function_by_owner(
                line.get("ReturnTypeTable"), line.get("ID"), "returnType"
            )
        else:
            ReturnType = self.call_c_function_by_id(
                line.get("ReturnTypeTable"), line.get("ReturnTypeTableSubId")
            )

        parameter = self.get_array_list("IType", line.get("ID"), "parameterTypes")

        return {
            "table": "CFunctionType",
            "returnType": ReturnType,
            "parameter": parameter,
        }

    def read_c_pointer_type(self, line):
        if line.get("TypeTableSubId") == 0:
            return {
                "table": "PointerType",
                "type": self.call_c_function_by_owner(
                    line.get("TypeTable"), line.get("ID"), "type"
                ),
            }
        else:
            return {
                "table": "PointerType",
                "type": self.call_c_function_by_id(
                    line.get("TypeTable"), line.get("TypeTableSubId")
                ),
            }

    def read_c_qualifier_type(self, line):
        if line.get("TypeTableSubId") == 0:
            return {
                "table": "QualifierType",
                "type": self.call_c_function_by_owner(
                    line.get("TypeTable"), line.get("ID"), "type"
                ),
            }
        else:
            return {
                "table": "QualifierType",
                "type": self.call_c_function_by_id(
                    line.get("TypeTable"), line.get("TypeTableSubId")
                ),
            }

    def read_c_enumeration(self, line):
        name = line.get("Name")
        if IDAtools.is_in_ida("Enumeration", name):
            return {"table": "PDOMCEnumeration", "name": name}

        enumerators = self.get_array_list("IEnumerator", line.get("ID"), "enumerators")
        result = {"table": "PDOMCEnumeration", "name": name, "enumerators": enumerators}
        self.symbol_builder.build_enum(result)
        return result

    def read_c_enumerator(self, line):
        name = line.get("Name")
        value = line.get("Value")
        return {"table": "PDOMCEnumerator", "name": name, "value": value}

    def read_c_field(self, line):
        name = line.get("Name")
        if line.get("TypeTableSubId") == 0:
            type = self.call_c_function_by_owner(
                line.get("TypeTable"), line.get("ID"), "type"
            )
        else:
            type = self.call_c_function_by_id(
                line.get("TypeTable"), line.get("TypeTableSubId")
            )

        return {"table": "PDOMCField", "name": name, "type": type}

    def read_c_function(self, line):
        name = line.get("Name")
        parameter = self.get_array_list("IParameter", line.get("ID"), "parameters")
        functionType = self.call_c_function_by_owner(
            line.get("TypeTable"), line.get("ID"), "type"
        )

        result = {
            "table": "PDOMCFunction",
            "name": name,
            "parameter": parameter,
            "functionType": functionType,
        }

        if IDAtools.is_in_ida("CFunction", name):
            return result
        self.symbol_builder.build_function(result)
        return result

    def read_c_parameter(self, line):
        return {"table": "PDOMCParameter", "name": line.get("Name")}

    def read_c_structure(self, line):
        name = line.get("Name")

        if IDAtools.is_in_ida("Structure", name):
            return {"table": "PDOMCStructure", "name": name}

        fields = self.get_array_list("IField", line.get("ID"), "fields")

        result = {"table": "PDOMCStructure", "name": name, "fields": fields}

        self.symbol_builder.build_struct(result)
        return result

    def read_c_typedef(self, line):
        name = line.get("Name")

        if line.get("TypeTableSubId") == 0:
            type = self.call_c_function_by_owner(
                line.get("TypeTable"), line.get("ID"), "type"
            )
        else:
            type = self.call_c_function_by_id(
                line.get("TypeTable"), line.get("TypeTableSubId")
            )

        reslut = {"table": "PDOMCTypedef", "name": name, "type": type}

        if IDAtools.is_in_ida("Typedef", name):
            return reslut
        self.symbol_builder.build_typedef(reslut)
        return reslut

    def read_c_variable(self, line):
        name = line.get("Name")

        if line.get("TypeTableSubId") == 0:
            type = self.call_c_function_by_owner(
                line.get("TypeTable"), line.get("ID"), "type"
            )
        else:
            type = self.call_c_function_by_id(
                line.get("TypeTable"), line.get("TypeTableSubId")
            )

        result = {"table": "PDOMCVariable", "name": name, "type": type}

        if IDAtools.is_in_ida("Variable", name):
            return result
        self.symbol_builder.build_global_variable(result)
        return result
