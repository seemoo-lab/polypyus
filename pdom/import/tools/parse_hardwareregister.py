import csv

class ParseHardwareregisterFile:

	def get_register(file_path):
		imputFile = open(file_path, 'r') 
		file_lines = imputFile.readlines() 
		list_regs = []
		for lines in file_lines:
			lines.strip()
			lines = lines.split(" ")
			lines = list(filter(None, lines))
			if lines[0] == '#define':
				list_regs.append(lines)

		output_list = []
		list_index = 0
		for lines in list_regs:
			try:
				addr = int(lines[2],16)
				name = list_regs[list_index+1][1]
				type = ""
				#IDA cant import "*(*(volatile unsigned int *)base_mac154_top_adr)" as type??
				#type = "volatile unsigned int * " + name

				#parse type:
				line_string = ''.join(list_regs[list_index+1])
				string_index = 0
				typeString = ""
				while line_string[string_index] is not "(":
					string_index = string_index +1
				scope = 1
				while scope is not 0:
					string_index = string_index +1
					if line_string[string_index] is "(":
						scope = scope +1
					if line_string[string_index] is ")":
						scope = scope -1
					if scope != 0:
						typeString = typeString + line_string[string_index]					
				
				output_list.append({'name': name, 'addr': addr,'size': '4' ,'type': typeString})
			except Exception:
				pass
			list_index =list_index +1

		return output_list


	def get_segments(file_path):

		segments = []

		def filterString(string):
			not_allowed = ["last_", "_last", "_end", "end_", "base_", "_base", "_start", "start_"]
			for s in not_allowed:
				if s in string:
					return False
			return True

		#get register and filter base and last definitions
		register = ParseHardwareregisterFile.get_register(file_path)
		register = list(filter(lambda x: filterString(x.get("name")), register))

		#map register in intervals with +- tolerance
		tolerance = 10000 #byte
		for regs in register:
			addr = regs.get("addr")
			ok = False
			for segment in segments:				
				if (addr + tolerance - segment.get("start")) >= 0 and (addr - tolerance - segment.get("end")) <= 0:
					segment.get("register").append(regs)
					if addr < segment.get("start"):
						segment["start"] = addr
					if addr > segment.get("end"):
						segment["end"] = addr+4
					ok = True
			if not ok:
				segments.append({"name" : "hardware_register_segment_" + str(len(segments)), "start" : addr, "end" : addr+4, "R":  1,"W":  1,"X":  0,"D": 0 ,"L": 0 ,"align": 0 ,"base": 00 ,"type":  "","class":""  ,"ad": 32 ,"T": 00 ,"DS":  00, "register" : []})

		#filter if a segment has < minRegisterCount register
		minRegisterCount = 10
		segments = list(filter(lambda x: len(x.get("register")) > minRegisterCount, segments))

		return segments