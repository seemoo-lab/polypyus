from tools.ida_tools import IDAtools

class CppReader:
	sql_controller = None
	symbol_builder = None

	def __init__(self, sqlControler, symbolBuilder):
		self.sql_controller = sqlControler
		self.symbol_builder = symbolBuilder


	def call_cpp_function_by_owner(self, table, ownerID, ownerVar):
		if table == "":
			return
		if table == "ProblemBinding":
			return 
		if table == "ProblemType":
			return		
		if table == "CPPArrayType":
			return self.read_cpp_array_type(self.sql_controller.get_entry_by_owner_id ("CPPArrayType",ownerID,ownerVar))		
		if table == "CPPBasicType":
			return self.read_cpp_basic_type(self.sql_controller.get_entry_by_owner_id ("CPPBasicType",ownerID,ownerVar))		
		if table == "CPPClassInstance":
			return self.read_cpp_class_instance_type(self.sql_controller.get_entry_by_owner_id ("CPPClassInstance",ownerID,ownerVar))		
		if table == "CPPClassSpecializationScope":
			return self.read_cpp_class_specialization_scope_type(self.sql_controller.get_entry_by_owner_id ("CPPClassSpecializationScope",ownerID,ownerVar))		
		if table == "CPPFieldSpecialization":
			return self.read_cpp_field_specialization_type(self.sql_controller.get_entry_by_owner_id ("CPPFieldSpecialization",ownerID,ownerVar))		
		if table == "CPPFunctionType":
			return self.read_cpp_function_type(self.sql_controller.get_entry_by_owner_id ("CPPFunctionType",ownerID,ownerVar))		
		if table == "CPPMethodSpecialization":
			return self.read_cpp_method_specialization_type(self.sql_controller.get_entry_by_owner_id ("CPPMethodSpecialization",ownerID,ownerVar))		
		if table == "CPPConstructorSpecialization":
			return self.read_cpp_constructor_specialization_type(self.sql_controller.get_entry_by_owner_id ("CPPConstructorSpecialization",ownerID,ownerVar))		
		if table == "CPPParameterPackType":
			return self.read_cpp_parameter_pack_type(self.sql_controller.get_entry_by_owner_id ("CPPParameterPackType",ownerID,ownerVar))		
		if table == "CPPParameterSpecialization":
			return self.read_cpp_parameter_specialization_type(self.sql_controller.get_entry_by_owner_id ("CPPParameterSpecialization",ownerID,ownerVar))		
		if table == "CPPPointerType":
			return self.read_cpp_pointer_type(self.sql_controller.get_entry_by_owner_id ("CPPPointerType",ownerID,ownerVar))		
		if table == "CPPQualifierType":
			return self.read_cpp_qualifier_type(self.sql_controller.get_entry_by_owner_id ("CPPQualifierType",ownerID,ownerVar))		
		if table == "CPPReferenceType":
			return self.read_cpp_reference_type(self.sql_controller.get_entry_by_owner_id ("CPPReferenceType",ownerID,ownerVar))		
		if table == "CPPTemplateTypeArgument":
			return self.read_cpp_template_type_argument_type(self.sql_controller.get_entry_by_owner_id ("CPPTemplateTypeArgument",ownerID,ownerVar))		
		if table == "CPPTemplateNonTypeArgument":
			return self.read_cpp_template_non_type_argument_type(self.sql_controller.get_entry_by_owner_id ("CPPTemplateNonTypeArgument",ownerID,ownerVar))		
		if table == "CPPTypedefSpecialization":
			return self.read_cpp_typedef_specialization_type(self.sql_controller.get_entry_by_owner_id ("CPPTypedefSpecialization",ownerID,ownerVar))

		if table == "PDOMCPPAliasTemplate":
			return self.read_cpp_alias_template(self.sql_controller.get_entry_by_owner_id ("PDOMCPPAliasTemplate",ownerID,ownerVar))		
		if table == "PDOMCPPClassType":
			return self.read_cpp_class_type(self.sql_controller.get_entry_by_owner_id ("PDOMCPPClassType",ownerID,ownerVar))		
		if table == "PDOMCPPClassInstance":
			return self.read_cpp_class_instance(self.sql_controller.get_entry_by_owner_id ("PDOMCPPClassInstance",ownerID,ownerVar))		
		if table == "PDOMCPPClassSpecialization":
			return self.read_cpp_class_specialization(self.sql_controller.get_entry_by_owner_id ("PDOMCPPClassSpecialization",ownerID,ownerVar))		
		if table == "PDOMCPPClassTemplate":
			return self.read_cpp_class_template(self.sql_controller.get_entry_by_owner_id ("PDOMCPPClassTemplate",ownerID,ownerVar))		
		if table == "PDOMCPPClassTemplatePartialSpecialization":
			return self.read_cpp_class_template_partial_specialization(self.sql_controller.get_entry_by_owner_id ("PDOMCPPClassTemplatePartialSpecialization",ownerID,ownerVar))		
		if table == "PDOMCPPEnumeration":
			return self.read_cpp_enumeration(self.sql_controller.get_entry_by_owner_id ("PDOMCPPEnumeration",ownerID,ownerVar))		
		if table == "PDOMCPPEnumerator":
			return self.read_cpp_enumerator(self.sql_controller.get_entry_by_owner_id ("PDOMCPPEnumerator",ownerID,ownerVar))		
		if table == "PDOMCPPField":
			return self.read_cpp_field(self.sql_controller.get_entry_by_owner_id ("PDOMCPPField",ownerID,ownerVar))		
		if table == "PDOMCPPFieldSpecialization":
			return self.read_cpp_field_specialization(self.sql_controller.get_entry_by_owner_id ("PDOMCPPFieldSpecialization",ownerID,ownerVar))		
		if table == "PDOMCPPFunction":
			return self.read_cpp_function(self.sql_controller.get_entry_by_owner_id ("PDOMCPPFunction",ownerID,ownerVar))		
		if table == "PDOMCPPMethod":
			return self.read_cpp_method(self.sql_controller.get_entry_by_owner_id ("PDOMCPPMethod",ownerID,ownerVar))		
		if table == "PDOMCPPConstructor":
			return self.read_cpp_constructor(self.sql_controller.get_entry_by_owner_id ("PDOMCPPConstructor",ownerID,ownerVar))		
		if table == "PDOMCPPFunctionInstance":
			return self.read_cpp_function_instance(self.sql_controller.get_entry_by_owner_id ("PDOMCPPFunctionInstance",ownerID,ownerVar))		
		if table == "PDOMCPPMethodInstance":
			return self.read_cpp_method_instance(self.sql_controller.get_entry_by_owner_id ("PDOMCPPMethodInstance",ownerID,ownerVar))		
		if table == "PDOMCPPMethodSpecialization":
			return self.read_cpp_method_specialization(self.sql_controller.get_entry_by_owner_id ("PDOMCPPMethodSpecialization",ownerID,ownerVar))		
		if table == "PDOMCPPFunctionTemplate":
			return self.read_cpp_function_template(self.sql_controller.get_entry_by_owner_id ("PDOMCPPFunctionTemplate",ownerID,ownerVar))		
		if table == "PDOMCPPMethodTemplate":
			return self.read_cpp_method_template(self.sql_controller.get_entry_by_owner_id ("PDOMCPPMethodTemplate",ownerID,ownerVar))		
		if table == "PDOMCPPMethodTemplateSpecialization":
			return self.read_cpp_method_template_specialization(self.sql_controller.get_entry_by_owner_id ("PDOMCPPMethodTemplateSpecialization",ownerID,ownerVar))		
		if table == "PDOMCPPConstructorTemplate":
			return self.read_cpp_constructor_template(self.sql_controller.get_entry_by_owner_id ("PDOMCPPConstructorTemplate",ownerID,ownerVar))		
		if table == "PDOMCPPParameter":
			return self.read_cpp_parameter(self.sql_controller.get_entry_by_owner_id ("PDOMCPPParameter",ownerID,ownerVar))		
		if table == "PDOMCPPParameterSpecialization":
			return self.read_cpp_parameter_specialization(self.sql_controller.get_entry_by_owner_id ("PDOMCPPParameterSpecialization",ownerID,ownerVar))		
		if table == "PDOMCPPTemplateNonTypeParameter":
			return self.read_cpp_template_non_type_parameter(self.sql_controller.get_entry_by_owner_id ("PDOMCPPTemplateNonTypeParameter",ownerID,ownerVar))		
		if table == "PDOMCPPTemplateTemplateParameter":
			return self.read_cpp_template_template_parameter(self.sql_controller.get_entry_by_owner_id ("PDOMCPPTemplateTemplateParameter",ownerID,ownerVar))		
		if table == "PDOMCPPTemplateTypeParameter":
			return self.read_cpp_template_type_parameter(self.sql_controller.get_entry_by_owner_id ("PDOMCPPTemplateTypeParameter",ownerID,ownerVar))		
		if table == "PDOMCPPTypedef":
			return self.read_cpp_typedef(self.sql_controller.get_entry_by_owner_id ("PDOMCPPTypedef",ownerID,ownerVar))		
		if table == "PDOMCPPTypedefSpecialization":
			return self.read_cpp_typedef_specialization(self.sql_controller.get_entry_by_owner_id ("PDOMCPPTypedefSpecialization",ownerID,ownerVar))		
		if table == "PDOMCPPVariable":
			return self.read_cpp_variable(self.sql_controller.get_entry_by_owner_id ("PDOMCPPVariable",ownerID,ownerVar))				


	def call_cpp_function_by_id(self, table, ID):

		if table == "":
			return
		if table == "ProblemBinding":
			return 
		if table == "ProblemType":
			return 
		
		if table == "CPPArrayType":
			return self.read_cpp_array_type(self.sql_controller.get_entry_by_id("CPPArrayType",ID))		
		if table == "CPPBasicType":
			return self.read_cpp_basic_type(self.sql_controller.get_entry_by_id("CPPBasicType",ID))		
		if table == "CPPClassInstance":
			return self.read_cpp_class_instance_type(self.sql_controller.get_entry_by_id("CPPClassInstance",ID))		
		if table == "CPPClassSpecializationScope":
			return self.read_cpp_class_specialization_scope_type(self.sql_controller.get_entry_by_id("CPPClassSpecializationScope",ID))		
		if table == "CPPFieldSpecialization":
			return self.read_cpp_field_specialization_type(self.sql_controller.get_entry_by_id("CPPFieldSpecialization",ID))		
		if table == "CPPFunctionType":
			return self.read_cpp_function_type(self.sql_controller.get_entry_by_id("CPPFunctionType",ID))		
		if table == "CPPMethodSpecialization":
			return self.read_cpp_method_specialization_type(self.sql_controller.get_entry_by_id("CPPMethodSpecialization",ID))		
		if table == "CPPConstructorSpecialization":
			return self.read_cpp_constructor_specialization_type(self.sql_controller.get_entry_by_id("CPPConstructorSpecialization",ID))		
		if table == "CPPParameterPackType":
			return self.read_cpp_parameter_pack_type(self.sql_controller.get_entry_by_id("CPPParameterPackType",ID))		
		if table == "CPPParameterSpecialization":
			return self.read_cpp_parameter_specialization_type(self.sql_controller.get_entry_by_id("CPPParameterSpecialization",ID))		
		if table == "CPPPointerType":
			return self.read_cpp_pointer_type(self.sql_controller.get_entry_by_id("CPPPointerType",ID))		
		if table == "CPPQualifierType":
			return self.read_cpp_qualifier_type(self.sql_controller.get_entry_by_id("CPPQualifierType",ID))		
		if table == "CPPReferenceType":
			return self.read_cpp_reference_type(self.sql_controller.get_entry_by_id("CPPReferenceType",ID))		
		if table == "CPPTemplateTypeArgument":
			return self.read_cpp_template_type_argument(self.sql_controller.get_entry_by_id("CPPTemplateTypeArgument",ID))		
		if table == "CPPTemplateNonTypeArgument":
			return self.read_cpp_template_non_type_argument(self.sql_controller.get_entry_by_id("CPPTemplateNonTypeArgument",ID))		
		if table == "CPPTypedefSpecialization":
			return self.read_cpp_typedef_specialization(self.sql_controller.get_entry_by_id("CPPTypedefSpecialization",ID))

		if table == "PDOMCPPAliasTemplate":
			return self.read_cpp_alias_template(self.sql_controller.get_entry_by_id("PDOMCPPAliasTemplate",ID))		
		if table == "PDOMCPPClassType":
			return self.read_cpp_class_type(self.sql_controller.get_entry_by_id("PDOMCPPClassType",ID))		
		if table == "PDOMCPPClassInstance":
			return self.read_cpp_class_instance(self.sql_controller.get_entry_by_id("PDOMCPPClassInstance",ID))		
		if table == "PDOMCPPClassSpecialization":
			return self.read_cpp_class_specialization(self.sql_controller.get_entry_by_id("PDOMCPPClassSpecialization",ID))		
		if table == "PDOMCPPClassTemplate":
			return self.read_cpp_class_template(self.sql_controller.get_entry_by_id("PDOMCPPClassTemplate",ID))		
		if table == "PDOMCPPClassTemplatePartialSpecialization":
			return self.read_cpp_class_template_partial_specialization(self.sql_controller.get_entry_by_id("PDOMCPPClassTemplatePartialSpecialization",ID))		
		if table == "PDOMCPPEnumeration":
			return self.read_cpp_enumeration(self.sql_controller.get_entry_by_id("PDOMCPPEnumeration",ID))		
		if table == "PDOMCPPEnumerator":
			return self.read_cpp_enumerator(self.sql_controller.get_entry_by_id("PDOMCPPEnumerator",ID))		
		if table == "PDOMCPPField":
			return self.read_cpp_field(self.sql_controller.get_entry_by_id("PDOMCPPField",ID))		
		if table == "PDOMCPPFieldSpecialization":
			return self.read_cpp_field_specialization(self.sql_controller.get_entry_by_id("PDOMCPPFieldSpecialization",ID))		
		if table == "PDOMCPPFunction":
			return self.read_cpp_function(self.sql_controller.get_entry_by_id("PDOMCPPFunction",ID))		
		if table == "PDOMCPPMethod":
			return self.read_cpp_method(self.sql_controller.get_entry_by_id("PDOMCPPMethod",ID))		
		if table == "PDOMCPPConstructor":
			return self.read_cpp_constructor(self.sql_controller.get_entry_by_id("PDOMCPPConstructor",ID))		
		if table == "PDOMCPPFunctionInstance":
			return self.read_cpp_function_instance(self.sql_controller.get_entry_by_id("PDOMCPPFunctionInstance",ID))		
		if table == "PDOMCPPMethodInstance":
			return self.read_cpp_method_instance(self.sql_controller.get_entry_by_id("PDOMCPPMethodInstance",ID))		
		if table == "PDOMCPPMethodSpecialization":
			return self.read_cpp_method_specialization(self.sql_controller.get_entry_by_id("PDOMCPPMethodSpecialization",ID))		
		if table == "PDOMCPPFunctionTemplate":
			return self.read_cpp_function_template(self.sql_controller.get_entry_by_id("PDOMCPPFunctionTemplate",ID))		
		if table == "PDOMCPPMethodTemplate":
			return self.read_cpp_method_template(self.sql_controller.get_entry_by_id("PDOMCPPMethodTemplate",ID))		
		if table == "PDOMCPPMethodTemplateSpecialization":
			return self.read_cpp_method_template_specialization(self.sql_controller.get_entry_by_id("PDOMCPPMethodTemplateSpecialization",ID))		
		if table == "PDOMCPPConstructorTemplate":
			return self.read_cpp_constructor_template(self.sql_controller.get_entry_by_id("PDOMCPPConstructorTemplate",ID))		
		if table == "PDOMCPPParameter":
			return self.read_cpp_parameter(self.sql_controller.get_entry_by_id("PDOMCPPParameter",ID))		
		if table == "PDOMCPPParameterSpecialization":
			return self.read_cpp_parameter_specialization(self.sql_controller.get_entry_by_id("PDOMCPPParameterSpecialization",ID))		
		if table == "PDOMCPPTemplateNonTypeParameter":
			return self.read_cpp_template_non_type_parameter(self.sql_controller.get_entry_by_id("PDOMCPPTemplateNonTypeParameter",ID))		
		if table == "PDOMCPPTemplateTemplateParameter":
			return self.read_cpp_template_template_parameter(self.sql_controller.get_entry_by_id("PDOMCPPTemplateTemplateParameter",ID))		
		if table == "PDOMCPPTemplateTypeParameter":
			return self.read_cpp_template_type_parameter(self.sql_controller.get_entry_by_id("PDOMCPPTemplateTypeParameter",ID))		
		if table == "PDOMCPPTypedef":
			return self.read_cpp_typedef(self.sql_controller.get_entry_by_id("PDOMCPPTypedef",ID))		
		if table == "PDOMCPPTypedefSpecialization":
			return self.read_cpp_typedef_specialization(self.sql_controller.get_entry_by_id("PDOMCPPTypedefSpecialization",ID))		
		if table == "PDOMCPPVariable":
			return self.read_cpp_variable(self.sql_controller.get_entry_by_id("PDOMCPPVariable",ID))
	

	def get_array_list(self, table, ID,var):
		parameterList = self.sql_controller.get_entry_by_owner_id_array(str(table), ID, var)
		parameter = []
		if isinstance(parameterList, list): 
			for entries in parameterList:
				ArrayPos = 0
				if table != "BTreeIndex":
					ArrayPos = entries.get("ArrayPos")
				if entries.get("TableRefSubId") == 0:
					parameter.append([ArrayPos, self.call_cpp_function_by_owner(entries.get("TableRef"), entries.get("ID"), entries.get("OwnerVariable"))])
				else:
					parameter.append([ArrayPos, self.call_cpp_function_by_id(entries.get("TableRef"), entries.get("TableRefSubId"))])
			return parameter
		else:
			ArrayPos = 0
			if table != "BTreeIndex":
				ArrayPos = parameterList.get("ArrayPos")
			if parameterList.get("TableRefSubId") == 0:
				return [[ArrayPos, self.call_cpp_function_by_owner(parameterList.get("TableRef"), parameterList.get("ID"), parameterList.get("OwnerVariable"))]]
			else:
				return [[ArrayPos, self.call_cpp_function_by_id(parameterList.get("TableRef"), parameterList.get("TableRefSubId"))]]


	def read_cpp_array_type(self, line):
		size = line.get("size")
		if(not size):
			size = 0

		if line.get("TypeTableSubId") == 0:
			return {"table":"ArrayType", "size": size, "type": self.call_cpp_function_by_owner(line.get("TypeTable"), line.get("ID"), "type")}
		else:
			return {"table":"ArrayType", "size": size, "type":  self.call_cpp_function_by_id(line.get("TypeTable"), line.get("TypeTableSubId"))}

	
	def read_cpp_basic_type(self, line):
		return {"table": "BasicType", "name":line.get("Name")}


	def read_cpp_class_instance_type(self, line):
		name = line.get("Name")
		if IDAtools.is_in_ida("Structure", name):
			return {"table": "CPPClassInstance","name" : name}		

		fields = self.get_array_list("IField", line.get("ID"),"fields")
		methods = self.get_array_list("ICPPMethod", line.get("ID"),"methods")	

		result = {"table": "CPPClassInstance", "name":line.get("Name"),"fields": fields,"methods": methods}
		
		self.symbol_builder.build_class_type(result)
		return result


	def read_cpp_class_specialization_scope_type(self, line):
		name = line.get("Name")	
		if line.get("ClassTypeTableSubId") == 0:
			classType = self.call_cpp_function_by_owner(line.get("ClassTypeTable"), line.get("ID"),"classType")
		else:
			classType = self.call_cpp_function_by_id(line.get("ClassTypeTable"), line.get("ClassTypeTableSubId"))

		constructors = self.get_array_list("ICPPConstructor", line.get("ID"),"constructors")
		implicitMethods = self.get_array_list("ICPPMethod", line.get("ID"),"implicitMethods")

		return {"table": "CPPClassSpecializationScope", "Name":line.get("Name")}


	def read_cpp_field_specialization_type(self, line):
		name = line.get("Name")
		typeTable = line.get("TypeTable")	
		fieldPosition = line.get("fieldPosition")

		if line.get("TypeTableSubId") == 0:
			type = self.call_cpp_function_by_owner(line.get("TypeTable"), line.get("ID"), "type")
		else:
			type = self.call_cpp_function_by_id(line.get("TypeTable"), line.get("TypeTableSubId"))	

		return {"table":"CPPFieldSpecialization","name" :name , "type" :type}


	def read_cpp_function_type(self, line):
		if line.get("ReturnTypeTableSubId") == 0:
			ReturnType = self.call_cpp_function_by_owner(line.get("ReturnTypeTable"), line.get("ID"), "returnType")
		else:
			ReturnType = self.call_cpp_function_by_id(line.get("ReturnTypeTable"), line.get("ReturnTypeTableSubId"))

		parameter = self.get_array_list("IType", line.get("ID"), "parameterTypes")

		return {"table":"CPPFunctionType","returnType":ReturnType, "parameter": parameter}


	def read_cpp_method_specialization_type(self, line):
		name = line.get("Name")
		parameter = self.get_array_list("ICPPParameter",line.get("ID"), "parameters")
		functionType = self.call_cpp_function_by_owner(line.get("TypeTable"),line.get("ID"),"type")

		if IDAtools.is_in_ida("CPPFunction", name):
			return {"table":"CPPMethodSpecialization","name":name ,"parameter":parameter,"functionType":functionType}

		result = {"table":"CPPMethodSpecialization","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}
		self.symbol_builder.build_function(result)
		return result


	def read_cpp_constructor_specialization_type(self, line):
		name = line.get("Name")
		parameter = self.get_array_list("ICPPParameter",line.get("ID"), "parameters")
		functionType = self.call_cpp_function_by_owner(line.get("TypeTable"),line.get("ID"),"type")

		if IDAtools.is_in_ida("CPPFunction", name):
			return {"table":"CPPConstructorSpecialization","name":name ,"parameter":parameter,"functionType":functionType}

		result = {"table":"CPPConstructorSpecialization","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}
		self.symbol_builder.build_function(result)
		return result


	def read_cpp_parameter_pack_type(self, line):
		name = line.get("Name")
		typeTable = line.get("TypeTable")	

		if line.get("TypeTableSubId") == 0:
			type = self.call_cpp_function_by_owner(line.get("TypeTable"), line.get("ID"), "type")
		else:
			type = self.call_cpp_function_by_id(line.get("TypeTable"), line.get("TypeTableSubId"))	

		return {"table":"CPPParameterPackType","name" :name , "type" :type}


	def read_cpp_parameter_specialization_type(self, line):
		name = line.get("Name")
		typeTable = line.get("TypeTable")	

		if line.get("TypeTableSubId") == 0:
			type = self.call_cpp_function_by_owner(line.get("TypeTable"), line.get("ID"), "type")
		else:
			type = self.call_cpp_function_by_id(line.get("TypeTable"), line.get("TypeTableSubId"))	

		return {"table":"CPPParameterSpecialization","name" :name , "type" :type}


	def read_cpp_pointer_type(self, line):
		if line.get("TypeTableSubId") == 0:
			return {"table":"PointerType", "type": self.call_cpp_function_by_owner(line.get("TypeTable"), line.get("ID"), "type")}
		else:
			return {"table":"PointerType", "type": self.call_cpp_function_by_id(line.get("TypeTable"), line.get("TypeTableSubId"))}


	def read_cpp_qualifier_type(self, line):
		if line.get("TypeTableSubId") == 0:
			return {"table":"QualifierType", "type": self.call_cpp_function_by_owner(line.get("TypeTable"), line.get("ID"), "type")}
		else:
			return {"table":"QualifierType", "type": self.call_cpp_function_by_id(line.get("TypeTable"), line.get("TypeTableSubId"))}


	def read_cpp_reference_type(self, line):
		if line.get("TypeTableSubId") == 0:
			return {"table":"ReferenceType", "type": self.call_cpp_function_by_owner(line.get("TypeTable"), line.get("ID"), "type")}
		else:
			return {"table":"ReferenceType", "type": self.call_cpp_function_by_id(line.get("TypeTable"), line.get("TypeTableSubId"))}


	def read_cpp_template_type_argument_type(self, line):
		return {"table": "CPPTemplateTypeArgument", "Name":line.get("Name")}


	def read_cpp_template_non_type_argument_type(self, line):
		return {"table": "CPPTemplateNonTypeArgument", "Name":line.get("Name")}


	def read_cpp_typedef_specialization_type(self, line):
		name = line.get("Name")			
		if line.get("TypeTableSubId") == 0:
			type = self.call_cpp_function_by_owner(line.get("TypeTable"), line.get("ID"), "typ")
		else:
			type = self.call_cpp_function_by_id(line.get("TypeTable"), line.get("TypeTableSubId"))

		reslut = {"table":"CPPTypedefSpecialization","name": name, "type" :type} 

		if IDAtools.is_in_ida("Typedef", name):
			return reslut
		self.symbol_builder.build_typedef(reslut)
		return  reslut


	def read_cpp_alias_template(self, line):
		return {"table": "PDOMCPPAliasTemplate", "Name":line.get("Name")}


	def read_cpp_class_type(self, line):
		name = line.get("Name")
		if IDAtools.is_in_ida("Structure", name):
			return {"table": "PDOMCPPClassType","name" : name}		

		fields = self.get_array_list("IField", line.get("ID"),"fields")
		methods = self.get_array_list("ICPPMethod", line.get("ID"),"methods")	

		result = {"table": "PDOMCPPClassType", "name":line.get("Name"),"fields": fields,"methods": methods}
		
		self.symbol_builder.build_class_type(result)
		return result
	 

	def read_cpp_class_instance(self, line):
		name = line.get("Name")
		if IDAtools.is_in_ida("Structure", name):
			return {"table": "PDOMCPPClassType","name" : name}

		fields = self.get_array_list("IField", line.get("ID"),"fields")
		methods = self.get_array_list("ICPPMethod", line.get("ID"),"methods")	

		result = {"table": "PDOMCPPClassInstance", "name":line.get("Name"),"fields": fields,"methods": methods}
		
		self.symbol_builder.build_class_type(result)
		return result

		
	def read_cpp_class_specialization(self, line):
		name = line.get("Name")
		if IDAtools.is_in_ida("Structure", name):
			return {"table": "PDOMCPPClassSpecialization","name" : name}

		fields = self.get_array_list("IField", line.get("ID"),"fields")
		methods = self.get_array_list("ICPPMethod", line.get("ID"),"methods")	

		result = {"table": "PDOMCPPClassSpecialization", "name":line.get("Name"),"fields": fields,"methods": methods}
		
		self.symbol_builder.build_class_type(result)
		return result

		
	def read_cpp_class_template(self, line):
		name = line.get("Name")
		if IDAtools.is_in_ida("Structure", name):
			return {"table": "PDOMCPPClassTemplate","name" : name}

		fields = self.get_array_list("IField", line.get("ID"),"fields")
		methods = self.get_array_list("ICPPMethod", line.get("ID"),"methods")	

		result = {"table": "PDOMCPPClassTemplate", "name":line.get("Name"),"fields": fields,"methods": methods}
		
		self.symbol_builder.build_class_type(result)
		return result

		
	def read_cpp_class_template_partial_specialization(self, line):
		name = line.get("Name")
		if IDAtools.is_in_ida("Structure", name):
			return {"table": "PDOMCPPClassTemplatePartialSpecialization","name" : name}

		fields = self.get_array_list("IField", line.get("ID"),"fields")
		methods = self.get_array_list("ICPPMethod", line.get("ID"),"methods")	

		result = {"table": "PDOMCPPClassTemplatePartialSpecialization", "name":line.get("Name"),"fields": fields,"methods": methods}
		
		self.symbol_builder.build_class_type(result)
		return result		


	def read_cpp_enumeration(self, line):
		name = line.get("Name")
		if IDAtools.is_in_ida("Enumeration", name):
			return {"table": "PDOMCPPEnumeration","name" : name}

		enumerators = self.get_array_list("IEnumerator", line.get("ID"),"enumerators")
		result = {"table":"PDOMCPPEnumeration","name" : name ,"enumerators" : enumerators}

		self.symbol_builder.build_enum(result)
		return result
		

	def read_cpp_enumerator(self, line):
		name = line.get("Name")
		value = line.get("Value")
		return {"table":"PDOMCPPEnumerator","name" :name , "value" :value}		


	def read_cpp_field(self, line):
		name = line.get("Name")
		typeTable = line.get("TypeTable")	
		fieldPosition = line.get("fieldPosition")

		if line.get("TypeTableSubId") == 0:
			type = self.call_cpp_function_by_owner(line.get("TypeTable"), line.get("ID"), "type")
		else:
			type = self.call_cpp_function_by_id(line.get("TypeTable"), line.get("TypeTableSubId"))	

		return {"table":"PDOMCPPField","name" :name , "type" :type}


	def read_cpp_field_specialization(self, line):
		return {"table": "PDOMCPPFieldSpecialization", "Name":line.get("Name")}


	def read_cpp_function(self, line):
		name = line.get("Name")
		argumentCount = line.get("requiredArgumentCount")
		parameter = self.get_array_list("ICPPParameter",line.get("ID"), "parameters")
		functionType = self.call_cpp_function_by_owner(line.get("TypeTable"),line.get("ID"),"type")

		if IDAtools.is_in_ida("CPPFunction", name):
			return {"table":"PDOMCPPFunction","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}

		result = {"table":"PDOMCPPFunction","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}
		self.symbol_builder.build_function(result)
		return result


	def read_cpp_method(self, line):
		name = line.get("Name")
		argumentCount = line.get("requiredArgumentCount")
		parameter = self.get_array_list("ICPPParameter",line.get("ID"), "parameters")
		functionType = self.call_cpp_function_by_owner(line.get("TypeTable"),line.get("ID"),"type")

		if IDAtools.is_in_ida("CPPMethod", name):
			return {"table":"PDOMCPPMethod","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}

		result =  {"table":"PDOMCPPMethod","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}
		self.symbol_builder.build_function(result)
		return result


	def read_cpp_constructor(self, line):
		name = line.get("Name")	
		argumentCount = line.get("requiredArgumentCount")
		parameter = self.get_array_list("ICPPParameter",line.get("ID"), "parameters")
		functionType = self.call_cpp_function_by_owner(line.get("TypeTable"),line.get("ID"),"type")

		if IDAtools.is_in_ida("CPPConstructor", name):
			return {"table":"PDOMCPPConstructor","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}


		result =  {"table":"PDOMCPPConstructor","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}
		self.symbol_builder.build_function(result)
		return result


	def read_cpp_function_instance(self, line):
		name = line.get("Name")
		argumentCount = line.get("requiredArgumentCount")
		parameter = self.get_array_list("ICPPParameter",line.get("ID"), "parameters")
		functionType = self.call_cpp_function_by_owner(line.get("TypeTable"),line.get("ID"),"funcType")

		if IDAtools.is_in_ida("CPPFunction", name):
			return {"table":"PDOMCPPFunctionInstance","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}

		result = {"table":"PDOMCPPFunctionInstance","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}
		self.symbol_builder.build_function(result)
		return result


	def read_cpp_method_instance(self, line):
		name = line.get("Name")
		argumentCount = line.get("requiredArgumentCount")
		parameter = self.get_array_list("ICPPParameter",line.get("ID"), "parameters")
		functionType = self.call_cpp_function_by_owner(line.get("TypeTable"),line.get("ID"),"type")

		if IDAtools.is_in_ida("CPPFunction", name):
			return {"table":"PDOMCPPMethodInstance","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}

		result = {"table":"PDOMCPPMethodInstance","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}
		self.symbol_builder.build_function(result)
		return result

		
	def read_cpp_method_specialization(self, line):
		name = line.get("Name")
		argumentCount = line.get("requiredArgumentCount")
		parameter = self.get_array_list("ICPPParameter",line.get("ID"), "parameters")
		functionType = self.call_cpp_function_by_owner(line.get("TypeTable"),line.get("ID"),"type")

		if IDAtools.is_in_ida("CPPMethod", name):
			return {"table":"PDOMCPPMethodSpecialization","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}


		result =  {"table":"PDOMCPPMethodSpecialization","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}
		self.symbol_builder.build_function(result)
		return result


	def read_cpp_function_template(self, line):
		name = line.get("Name")

		argumentCount = line.get("requiredArgumentCount")
		parameter = self.get_array_list("ICPPParameter",line.get("ID"), "parameters")
		functionType = self.call_cpp_function_by_owner(line.get("FunctionTypeTable"),line.get("ID"),"type")

		allInstances = self.get_array_list("ICPPTemplateInstance",line.get("ID"), "allInstances")
		templateParameters = self.get_array_list("IPDOMCPPTemplateParameter",line.get("ID"), "templateParameters")


		result = {"table":"PDOMCPPFunctionTemplate","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}

		if IDAtools.is_in_ida("CPPFunctionTemplate", name):
			return result

		self.symbol_builder.build_function(result)
		return result

		
	def read_cpp_method_template(self, line):
		name = line.get("Name")

		argumentCount = line.get("requiredArgumentCount")
		parameter = self.get_array_list("ICPPParameter",line.get("ID"), "parameters")
		functionType = self.call_cpp_function_by_owner(line.get("FunctionTypeTable"),line.get("ID"),"type")

		allInstances = self.get_array_list("ICPPTemplateInstance",line.get("ID"), "allInstances")
		templateParameters = self.get_array_list("IPDOMCPPTemplateParameter",line.get("ID"), "templateParameters")

		result = {"table":"PDOMCPPMethodTemplate","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}

		if IDAtools.is_in_ida("CPPFunctionTemplate", name):
			return result

		self.symbol_builder.build_function(result)
		return result


	def read_cpp_method_template_specialization(self, line):
		name = line.get("Name")

		argumentCount = line.get("requiredArgumentCount")
		parameter = self.get_array_list("ICPPParameter",line.get("ID"), "parameters")
		functionType = self.call_cpp_function_by_owner(line.get("TypeTable"),line.get("ID"),"type")

		allInstances = self.get_array_list("ICPPTemplateInstance",line.get("ID"), "allInstances")
		templateParameters = self.get_array_list("IPDOMCPPTemplateParameter",line.get("ID"), "templateParameters")

		result = {"table":"PDOMCPPMethodTemplateSpecialization","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}

		if IDAtools.is_in_ida("CPPFunctionTemplate", name):
			return result

		self.symbol_builder.build_function(result)
		return result

		
	def read_cpp_constructor_template(self, line):
		name = line.get("Name")

		argumentCount = line.get("requiredArgumentCount")
		parameter = self.get_array_list("ICPPParameter",line.get("ID"), "parameters")
		functionType = self.call_cpp_function_by_owner(line.get("FunctionTypeTable"),line.get("ID"),"type")

		allInstances = self.get_array_list("ICPPTemplateInstance",line.get("ID"), "allInstances")
		templateParameters = self.get_array_list("IPDOMCPPTemplateParameter",line.get("ID"), "templateParameters")


		result = {"table":"PDOMCPPConstructorTemplate","name":name,"argumentCount ": argumentCount ,"parameter":parameter,"functionType":functionType}

		if IDAtools.is_in_ida("CPPFunctionTemplate", name):
			return result

		self.symbol_builder.build_function(result)
		return result


	def read_cpp_parameter(self, line):
		return {"table": "PDOMCPPParameter", "name":line.get("Name")}

	def read_cpp_parameter_specialization(self, line):
		return {"table": "PDOMCPPParameterSpecialization", "name":line.get("Name")}

	def read_cpp_template_non_type_parameter(self, line):
		return {"table": "PDOMCPPParameterSpecialization", "name":line.get("Name"),"posistion" : line.get("parameterPosition")}

	def read_cpp_template_template_parameter(self, line):
		return {"table": "PDOMCPPParameterSpecialization", "name":line.get("Name"),"posistion" : line.get("parameterPosition")}

	def read_cpp_template_type_parameter(self, line):
		return {"table": "PDOMCPPTemplateTypeParameter", "name":line.get("Name"), "posistion" : line.get("parameterPosition")}		

		
	def read_cpp_typedef(self, line):
		name = line.get("Name")			
		if line.get("TypeTableSubId") == 0:
			type = self.call_cpp_function_by_owner(line.get("TypeTable"), line.get("ID"), "type")
		else:
			type = self.call_cpp_function_by_id(line.get("TypeTable"), line.get("TypeTableSubId"))

		result = {"table":"PDOMCPPTypedef","name": name, "type" :type} 

		if IDAtools.is_in_ida("Typedef", name):
			return result
		self.symbol_builder.build_typedef(result)
		return  result

		
	def read_cpp_typedef_specialization(self, line):
		name = line.get("Name")			
		if line.get("TypeTableSubId") == 0:
			type = self.call_cpp_function_by_owner(line.get("TypeTable"), line.get("ID"), "type")
		else:
			type = self.call_cpp_function_by_id(line.get("TypeTable"), line.get("TypeTableSubId"))

		result = {"table":"PDOMCPPTypedefSpecialization","name": name, "type" :type} 

		if IDAtools.is_in_ida("Typedef", name):
			return result
		self.symbol_builder.build_typedef(result)
		return  result


	def read_cpp_variable(self, line):
		name = line.get("Name")	

		if line.get("TypeTableSubId") == 0:
			type = self.call_cpp_function_by_owner(line.get("TypeTable"), line.get("ID"), "type")
		else:
			type = self.call_cpp_function_by_id(line.get("TypeTable"), line.get("TypeTableSubId"))	

		result = {"table":"PDOMCPPVariable","name": name , "type": type}

		if IDAtools.is_in_ida("Variable", name):
			return result
		self.symbol_builder.build_global_variable(result)
		return result