from tools.ida_tools import IDAtools

import csv

class SymbolBuilder:

	createCSV = False
	csvLines = []

	def __init__(self, createCSV):
		self.createCSV = createCSV
		self.csvLines = []
		

	def set_writeCSV(self,i):
		self.createCSV = i


	def clean_csvLines(self):
		self.csvLines = []


	def build_enum(self,line):
		if not self.createCSV:
			name = self.clean_name(line.get("name"))
			IDAtools.set_enum(name)
			enumerators = line.get("enumerators")
			for i in enumerators:
				IDAtools.set_enum_member(name, i[1].get("name"), i[1].get("value"))


	def build_function(self,line):
		name = self.clean_name(line.get("name"))
		parameter = line.get("parameter")
		functionType = line.get("functionType")

		if functionType != None:
			returntype = functionType.get("returnType")
			parametertypes = functionType.get("parameter")

			function_signature = self.get_type_string(returntype) + " " + name + "("
			if len(parameter) > len(parametertypes):
				parameter_count = len(parameter)
			else:
				parameter_count = len(parametertypes)

			for parameter_index in range(parameter_count):
				if parameter_index != 0:
					function_signature = function_signature + " ,"

				try:
					parameter_indentifier =  str(parameter[parameter_index][1].get("name"))
				except(IndexError, TypeError):
					parameter_indentifier = "UNKNOWN"

				if parameter_indentifier == " " or parameter_indentifier == "" or parameter_indentifier == None:
					parameter_indentifier = "UNKNOWN"

				try:
					parameter_type = self.get_type_string(parametertypes[parameter_index][1])
					if parameter_type == "" or parameter_type == " " or parameter_type == None:
						parameter_type = "_UNKNOWN"

					current_type = parametertypes[parameter_index][1]
					if current_type:
						if current_type.get("table") == "ArrayType":
							size = current_type.get("size")
							function_signature = function_signature + parameter_type + " " + parameter_indentifier + " [" + str(size) + "]"
						else:
							function_signature = function_signature + parameter_type + " " + parameter_indentifier
				except(IndexError):
					parameter_type = "_UNKNOWN"
					function_signature = function_signature + parameter_type + " " + parameter_indentifier				

			function_signature = function_signature + ")"
		else:
			function_signature = "void " + name + "()"

		if not self.createCSV:
			IDAtools.set_function_type(name, function_signature)
		else:
			self.csvLines.append([name, function_signature])


	def build_typedef(self,line):
		if not self.createCSV:
			localType_name = self.clean_name(line.get("name"))
			localType_type = self.get_type_string(line.get("type"))

			type_string = "typedef " + localType_type + " " + localType_name
			if (line.get("type")) and (line.get("type").get("table") == "ArrayType"):
				size = line.get("type").get("size")
				type_string = type_string +  " [" + str(size) + "]"

			IDAtools.set_local_type(type_string,localType_name)	


	def build_global_variable(self,line):
		if not self.createCSV:
			varibale_name = self.clean_name(line.get("name"))
			varibale_type = self.get_type_string(line.get("type"))
			typestring = str(varibale_type) + " " + str(varibale_name)

			if (line.get("type")) and line.get("type").get("table") == "ArrayType":
				size = line.get("type").get("size")
				typestring = typestring  +  " [" + str(size) + "]"

			IDAtools.set_global_data(varibale_name, typestring)


	def build_struct(self,line):
		if not self.createCSV:
			structname = self.clean_name(line.get("name"))
			IDAtools.set_struct(structname)
			
			fields = line.get("fields")
			for field in fields:
				try:
					if field[1].get("table") == "PDOMCPPConstructor" or field[1].get("table") == "PDOMCPPMethod" or field[1].get("table") == "PDOMCPPFunction" or field[1].get("table") == "PDOMCFunction":
						fieldName = field[1].get("name")
						type = field[1].get("functionType")
						size = IDAtools.get_size(fieldName,type.get("table"),type)
						flag_andTypeID = IDAtools.get_flag_and_id(size,type)
						IDAtools.set_struct_member(structname,fieldName, flag_andTypeID, size)
					else:
						fieldName = field[1].get("name")	
						type = field[1].get("type")
						size = 1
						if type:
							if type.get("table") == "BasicType" and field[1].get("table") =="PDOMCField":
								size = IDAtools.get_size(type.get("name"),type.get("table"),type)
							else:
								size = IDAtools.get_size(fieldName,type.get("table"),type)
						flag_andTypeID = IDAtools.get_flag_and_id(size,type)
						IDAtools.set_struct_member(structname,fieldName, flag_andTypeID, size)	
				except SyntaxError:
					pass


	def build_class_type(self,line):
		if not self.createCSV:
			name = self.clean_name(line.get("name"))
			fields = line.get("fields")
			methods = line.get("methods")

			name_mbrs = self.build_struct({"name" : name + "_mbrs", "fields" : fields})
			name_vtbl = self.build_struct({"name" : name + "_vtbl", "fields" : methods})
			field_membrs = [0, {'table': 'PDOMCField', 'name': "__mbrs", 'type': {'table': 'PDOMCPPTypedef',  'name': name + "_mbrs" }}]
			field_vtbl = [1, {'table': 'PDOMCField', 'name': "__vtbl", 'type':  {'table': 'PointerType', 'type': {'table': 'PDOMCPPTypedef',  'name': name + "_mbrs"}}}]
			self.build_struct({'name': name, 'fields': [field_vtbl,field_membrs]})


	def build_function_pointer(self,line):
		function_name = self.clean_name(line.get("name"))
		parameter = line.get("parameter")
		functionType = line.get("functionType")
		if functionType != None:
			returntype = functionType.get("returnType")
			parametertypes = functionType.get("parameter")
		else:
			return "void (*)()"

		function = self.get_type_string(returntype) + " (*" + function_name + ")("
		if len(parameter) > len(parametertypes):
			numparas = len(parameter)
		else:
			numparas = len(parametertypes)

		for i in range(numparas):
			if i != 0:
				function = function + " ,"
			try:
				parameterType = self.get_type_string(parametertypes[i][1])
				if (parameterType == ""):
					parameterType = "_UNKNOWN"

				curType = arametertypes[i][1]
				if curType:
					if curType.get("table") == "ArrayType":
						size = curType.get("size")
						function = function + parameterType +  " [" + str(size) + "]"
					else:
						function = function + parameterType + " "

			except(IndexError):
				parameterType = "_UNKNOWN"
				function = function + parameterType + " "

		return function + " )"	


	def get_type_string(self,type_dict):
		string = ""
		if type_dict == None:
			return "_UNKNOWN"
		try:
			while type_dict.get("table") != "BasicType" and not (type_dict.get("table").startswith("PDOM")):
				if type_dict.get("table") == "ReferenceType":
					string = string + " &"
				if type_dict.get("table") == "PointerType":
					string = string + " *"
				type_dict = type_dict.get("type")
		except(AttributeError):
			return "_UNKNOWN" + string

		if type_dict.get("name") == "":
		 	string = "_UNKNOWN" + string
		else:
			string = self.clean_name(type_dict.get("name")) + string

		return string


	def clean_name(self,name):
		name = name.replace("}","")
		name = name.replace("{","")
		name = name.replace(":","_")
		name = name.replace(".","_")
		return name


	def write_csv(self,csvPath,database_name):
		print("write CSV at ", csvPath)
		writer = csv.writer(open(csvPath, 'w'), delimiter=';')
		writer.writerow(["SymbolName", database_name])
		for line in self.csvLines:
			writer.writerow(line)