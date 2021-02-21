import csv
import time

class SignatureBuilder:

	def get_final_signature_csv(files, reference_PDOM ,final_csv_path):
		Dict = []
		header = []

		symbolDict = {}
		for filepath in files:
			reader = csv.reader(open(filepath, 'r'), delimiter=";")
			currentPDOM = ""
			for line in reader:
				symbol = line[0]
				signature = line[1]
				if signature == "" or symbol == "":
					continue
				if line[0] == "SymbolName":
					currentPDOM = line[1]
				else:
					if symbol in symbolDict:
						if signature in symbolDict[symbol]:
							symbolDict[symbol][signature].append(currentPDOM)
						else:
							symbolDict[symbol][signature] = [currentPDOM]
					else:
						symbolDict[symbol] = {signature : [currentPDOM]}
		
		finalSymbolMap = []
		for mappedSymbol in symbolDict:
			finalSymbolMap.append(SignatureBuilder.get_best_signature(mappedSymbol, symbolDict[mappedSymbol], reference_PDOM))

		return SignatureBuilder.write_csv(finalSymbolMap,final_csv_path)


	#####################################################################################

	def get_best_signature(symbol, signature_Dict, reference_PDOM):

		if len(signature_Dict) == 1: #return if there is just one signature available
			for i in signature_Dict: #do parse and build_parsed to correct buggy signatures
				return [symbol, SignatureBuilder.build_parsed_Function(SignatureBuilder.parse_function(i)), signature_Dict[i][0]]
		
		
		#create datastructure for choosing types
		possible_function_types_dict, possible_parameter_list = SignatureBuilder.get_possible_types(signature_Dict)

		#choose refernence signature
		reference_signature = SignatureBuilder.chosse_referenz_signature(signature_Dict,reference_PDOM)
		reference_signature_parsed = SignatureBuilder.parse_function(reference_signature)

		#save used pdoms for import
		usedPDOMS = [signature_Dict[reference_signature][0]]

		#choose function type		
		reference_signature_function_type = reference_signature_parsed.get("return") 
		if reference_signature_function_type == "_UNKNOWN" and possible_function_types_dict:
			decided_function_type = max(possible_function_types_dict, key = lambda type_: possible_function_types_dict.get(type_).get('count'))
			if decided_function_type == "":
				decided_function_type = "_UNKNOWN"
			else:
				usedPDOMS.append(possible_function_types_dict[decided_function_type]['pdom'])
		else:
			decided_function_type = reference_signature_function_type

		#choose parameter types
		decided_parameter_list = []
		parameter_index = -1
		for reference_parameter in reference_signature_parsed.get("parameter"):
			parameter_index = parameter_index + 1

			current_reference_parameter_type = reference_parameter.get('type')
			current_reference_parameter_name = reference_parameter.get('name')

			notUnknownParameter = []
			possible_parameter_list_known = []
			if current_reference_parameter_type == "_UNKNOWN" or current_reference_parameter_type == "":
				for types in possible_parameter_list[parameter_index][current_reference_parameter_name]:
					if types != "_UNKNOWN" and types != "":
						possible_parameter_list_known = { key:value for (key,value) in possible_parameter_list[parameter_index][current_reference_parameter_name].items() if not "_UNKNOWN" in key and key != ""}
						
				if len(possible_parameter_list_known) == 0:
					decidedParameter = "_UNKNOWN"
				else:
					decidedParameter = max(possible_parameter_list_known, key = lambda x: possible_parameter_list_known[x].get('count'))
					usedPDOMS.append(possible_parameter_list_known.get(decidedParameter).get("pdom"))

				decided_parameter_list.append(decidedParameter)
			else:
				decided_parameter_list.append(current_reference_parameter_type)

		#build signature from choosed types
		signature = SignatureBuilder.build_parsed_function_from_decided_types(decided_function_type,reference_signature_parsed,decided_parameter_list)
	
		#return signature with used pdom databases
		result = [reference_signature_parsed.get("name"), signature]
		pdom_list = list(dict.fromkeys(usedPDOMS))
		for pdom in pdom_list:
			result.append(pdom)

		return result
		

	def chosse_referenz_signature(signature_Dict, reference_PDOM):

		refSignature = ""
		if reference_PDOM != "":
			for signature in signature_Dict:
				for pdom in signature_Dict[signature]:
					if pdom == reference_PDOM:
						return signature

		return max(signature_Dict, key = lambda signature_: (len(SignatureBuilder.parse_function(signature_).get("parameter")), len(signature_Dict[signature_])))


	def get_possible_types(signature_Dict):
		possible_function_types_dict = {}
		possible_parameter_list = []

		for signature in signature_Dict:		
			parsedSignature = SignatureBuilder.parse_function(signature)
			
			current_parameter_list = parsedSignature.get("parameter")
			for parameter_Index in range(len(current_parameter_list)):
				current_parameter_type = current_parameter_list[parameter_Index].get("type")
				current_parameter_name = current_parameter_list[parameter_Index].get("name")
				try: 
					if current_parameter_name in possible_parameter_list[parameter_Index]:					
						if current_parameter_type in possible_parameter_list[parameter_Index][current_parameter_name]:
							possible_parameter_list[parameter_Index][current_parameter_name][current_parameter_type]['count'] = possible_parameter_list[parameter_Index].get(current_parameter_name).get(current_parameter_type).get('count') + 1
						else:
							possible_parameter_list[parameter_Index][current_parameter_name][current_parameter_type] = {'count' : 1, 'pdom' : signature_Dict[signature][0]}
					else:
						possible_parameter_list[parameter_Index][current_parameter_name] = {current_parameter_type: {'count' : 1, 'pdom' : signature_Dict[signature][0]}}
				except IndexError:
					possible_parameter_list.append({current_parameter_name: {current_parameter_type: {'count' : 1, 'pdom' : signature_Dict[signature][0]}}})

			current_function_type = parsedSignature.get("return")
			if not ( current_function_type in possible_function_types_dict) and current_function_type != "_UNKNOWN":
				possible_function_types_dict[current_function_type] = {'count' : 1, 'pdom' : signature_Dict[signature][0]}
			elif current_function_type != "_UNKNOWN":
				possible_function_types_dict[current_function_type]['count'] = possible_function_types_dict.get(current_function_type).get('count') +1

		return possible_function_types_dict, possible_parameter_list

	########################Global help Functions###############################################

	def build_parsed_Function(function_Dict):
		function = function_Dict.get("return") + " " + function_Dict.get("name") + "("
		parameter_list = function_Dict.get("parameter")

		if len(parameter_list) == 0:
			return function + ")"

		counter = 0
		for parameter_dict in parameter_list:
			if counter == len(parameter_list)-1:
				function = function + parameter_dict.get("type") + " " + parameter_dict.get("name") + ")"
			else:
				function = function + parameter_dict.get("type") + " " + parameter_dict.get("name") + ","
			counter = counter+1

		return function

	def build_parsed_function_from_decided_types(decided_function_type,reference_signature_parsed,decided_parameter_list):
		signature = decided_function_type + " " + reference_signature_parsed.get("name") + "("
		index = 0
		if len(decided_parameter_list) == 0:
			signature = signature + ")"

		for decided_parameter_types in decided_parameter_list:
			parameterName = reference_signature_parsed.get("parameter")[index].get("name")
			if decided_parameter_types == "" or decided_parameter_types == " " or decided_parameter_types is None:
				decided_parameter_types = "_UNKNOWN"
			if parameterName == "" or parameterName == " " or parameterName is None:
				parameterName = "UNKNOWN"
			if index == len(decided_parameter_list)-1:
				signature = signature + decided_parameter_types + " " + parameterName + ")"
			else:
				signature = signature + decided_parameter_types + " " + parameterName + ","
			index = index+1

		return signature


	def parse_function(functionString):
		#get list of tokens
		nextToken,index = SignatureBuilder.get_next_token(functionString, 0)
		tokens = []
		while nextToken != None:
			tokens.append(nextToken)
			nextToken , index = SignatureBuilder.get_next_token(functionString, index)

		#initialize function dictionary with parameter count as default _UNKNOWN
		parameterCounter = SignatureBuilder.get_parameter_count(tokens)
		functionDict = {}
		functionDict["parameter"] = [{"type": "_UNKNOWN", "name": "UNKNOWN"}] * parameterCounter
		functionDict["return"] = '_UNKNOWN'
		functionDict["name"] = 'UNKNOWN'

		#function signatures like "void foo(int a, , int * b)" are possible, thats the reason for all following cases
		#parses will fill missing types and idents with "_UNKNOWN", to keep the number of parameter
		parameter_index = parameterCounter -1
		index = len(tokens)-1
		while index > -1:
			#parse parameter
			if(tokens[index] == "," or tokens[index] == ")"):
				index = index-1
				if (parameter_index == -1):
					continue

				currentType = ''
				currentIdentifier = 'UNKNOWN'
				#parse identifier
				if tokens[index] != "," and tokens[index] != "(" and tokens[index] != ")":
					currentIdentifier = tokens[index]
					index = index-1
				
				#parse parameter types
				while tokens[index] != "," and tokens[index] != "(" and tokens[index] != ")":
					if currentType != '':
						currentType = tokens[index]  + " " + currentType
					else:
						currentType = tokens[index]
					index = index-1

				if currentType == '':
					currentType = '_UNKNOWN'
				functionDict["parameter"][parameter_index] = {"type": currentType, "name": currentIdentifier}
				parameter_index = parameter_index - 1

			#parse function type and name
			elif tokens[index] == "(":
				index = index-1
				currentIdentifier = tokens[index]
				index = index-1
				currentType = ''
				while(index >= 0):
					if currentType != '':
						currentType = tokens[index]  + " " + currentType
					else:
						currentType = tokens[index]
					index = index-1

				if currentType == '':
					currentType = '_UNKNOWN'

				functionDict["return"] = currentType
				functionDict["name"] = currentIdentifier

			else:
				index = index -1

		return functionDict

	def get_next_token(line, index):
		try:	
			currentToken = ""	
			if (line[index] == "," or line[index] == " " or line[index] == "(" or line[index] == ")"):	
				currentToken = currentToken + line[index]
				index = index +1
			else:
				while(line[index] != "," and line[index] != " " and line[index] != "(" and line[index] != ")"):			
					currentToken = currentToken + line[index]
					index = index +1
		except IndexError:
			return None, None

		if currentToken != " ":
			return currentToken.replace(' ','') , index
		else:
			return SignatureBuilder.get_next_token(line, index)

	def get_parameter_count(tokens):

		parameter_count = 0
		token_index = len(tokens)-1
		lastSeperator = ''
		lastToken = ''
		while token_index >= 0:
			if tokens[token_index] == ")":
				lastSeperator = ")"
			if tokens[token_index] == "(":
				if lastSeperator == ")" and lastToken == ")":
					break
				else:
					parameter_count = parameter_count +1
			if tokens[token_index] == ",":
				parameter_count = parameter_count +1
			lastToken = tokens[token_index]
			token_index = token_index -1

		return parameter_count


	def write_csv(list,path):
		csvName = path + "finalSymbols" + "." + str(time.time()) + ".csv"

		with open(csvName, 'w', newline='') as csvfile:
			symbolwriter = csv.writer(csvfile, delimiter=";", quotechar='|', quoting=csv.QUOTE_MINIMAL)
			for i in list:
				symbolwriter.writerow(i)

		return csvName

	###################################################################################
