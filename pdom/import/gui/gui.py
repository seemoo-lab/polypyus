import ida_kernwin

from PyQt5 import QtCore, QtGui, QtWidgets

from .controller import Controller

class GuiFromWindow(ida_kernwin.PluginForm):
 
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.create_gui()

    def OnClose(self, form):
        pass

    def create_gui(self):
       
        layout = QtWidgets.QFormLayout()
        
        #Import csv or .elf files
        self.headline_elf = QtWidgets.QLabel("Select elf,polypyus csv-export or import userdefined file")
        self.selectFile_btn_elf = QtWidgets.QPushButton("Select file")
        self.import_btn_elf = QtWidgets.QPushButton("Import")
        self.skip_btn_elf = QtWidgets.QPushButton("Skip")
        self.userdefined_csv_btn_elf = QtWidgets.QPushButton("Import userdefined file")
        self.import_functions_checkbox = QtWidgets.QCheckBox("Import functions")
        self.import_globals_checkbox = QtWidgets.QCheckBox("Import objects")
        self.import_sections_checkbox = QtWidgets.QCheckBox("Import segments")
        self.overwrite_names_elf_checkbox = QtWidgets.QCheckBox("Overwrite names")
        self.adjust_for_arm_thumb_checkbox =  QtWidgets.QCheckBox("Adjust for ARM Thumb mode")
        self.pathline_Elf = QtWidgets.QLineEdit()

        #import signatures
        self.headline_database = QtWidgets.QLabel("Select database for import\n Please note, all functiontypes and globaltypes will be overwritten")
        self.label_refDB = QtWidgets.QLabel("Reference DB")
        self.selectFile_btn_database = QtWidgets.QPushButton("Select database")        
        self.label_add_database = QtWidgets.QLabel("Additional Databases")
        self.list_DB = QtWidgets.QListWidget()
        self.getMultiplefiles_Database_to_List = QtWidgets.QPushButton("Select database")
        self.import_btn_database = QtWidgets.QPushButton("import")
        self.skip_btn_database = QtWidgets.QPushButton("skip")
        self.pathline_database = QtWidgets.QLineEdit()

        #import hardwareRegs
        self.headline_Regs = QtWidgets.QLabel("Select hardware register file for import")
        self.selectFile_btn_Regs = QtWidgets.QPushButton("Select file")
        self.import_btn_Regs = QtWidgets.QPushButton("Import")
        self.skip_btn_Regs = QtWidgets.QPushButton("Skip")
        self.names_checkbox_regs = QtWidgets.QCheckBox("Overwrite names")
        self.names_create_segments_regs = QtWidgets.QCheckBox("Create segments")
        self.pathline_Regs = QtWidgets.QLineEdit()

        #progress bar and state
        self.headline_Progress = QtWidgets.QLabel("Import...")
        self.state_label = QtWidgets.QLabel("")
        self.pbar = QtWidgets.QProgressBar() 
        self.pbar.setGeometry(30, 40, 200, 25)
       

        #define layout
        frameElf = QtWidgets.QFrame()
        fboxElf = QtWidgets.QFormLayout()
        fboxElf.addRow(self.headline_elf)
        vbox_Elf_FilePath = QtWidgets.QHBoxLayout()
        vbox_Elf_FilePath.addWidget(self.pathline_Elf)
        vbox_Elf_FilePath.addWidget(self.selectFile_btn_elf)        
        fboxElf.addRow(vbox_Elf_FilePath)
        vbox_Elf_Options = QtWidgets.QHBoxLayout()
        vbox_Elf_Options.addWidget(self.import_functions_checkbox)
        vbox_Elf_Options.addWidget(self.import_globals_checkbox)
        vbox_Elf_Options.addWidget(self.import_sections_checkbox)
        fboxElf.addRow(vbox_Elf_Options) 
        vbox_Elf_Options_Import = QtWidgets.QHBoxLayout()
        vbox_Elf_Options_Import.addWidget(self.overwrite_names_elf_checkbox)
        vbox_Elf_Options_Import.addWidget(self.adjust_for_arm_thumb_checkbox)
        fboxElf.addRow(vbox_Elf_Options_Import)
        vbox_Elf_Buttons = QtWidgets.QHBoxLayout()
        vbox_Elf_Buttons.addWidget(self.userdefined_csv_btn_elf)
        vbox_Elf_Buttons.addWidget(self.skip_btn_elf)
        vbox_Elf_Buttons.addWidget(self.import_btn_elf)
        fboxElf.addRow(vbox_Elf_Buttons) 
        frameElf.setLayout(fboxElf) 

        frameDB = QtWidgets.QFrame()
        fboxDB = QtWidgets.QFormLayout()
        fboxDB.addRow(self.headline_database)
        vboxDB_FilePath = QtWidgets.QHBoxLayout()
        vboxDB_FilePath.addWidget(self.label_refDB)
        vboxDB_FilePath.addWidget(self.pathline_database)
        vboxDB_FilePath.addWidget(self.selectFile_btn_database)
        fboxDB.addRow(vboxDB_FilePath)
        fboxDB.addRow(self.label_add_database)
        vboxDB_list_DB = QtWidgets.QHBoxLayout()
        vboxDB_list_DB.addWidget(self.list_DB)
        vboxDB_list_DB.addWidget(self.getMultiplefiles_Database_to_List)
        fboxDB.addRow(vboxDB_list_DB) 
        vboxDB_Buttons = QtWidgets.QHBoxLayout()
        vboxDB_Buttons.addWidget(self.skip_btn_database)
        vboxDB_Buttons.addWidget(self.import_btn_database)
        fboxDB.addRow(vboxDB_Buttons) 
        frameDB.setLayout(fboxDB) 

        frameHardwareRegs = QtWidgets.QFrame()
        fboxRegs = QtWidgets.QFormLayout()
        fboxRegs.addRow(self.headline_Regs)
        vboxRegs_FilePath = QtWidgets.QHBoxLayout()
        vboxRegs_FilePath.addWidget(self.pathline_Regs)
        vboxRegs_FilePath.addWidget(self.selectFile_btn_Regs)
        fboxRegs.addRow(vboxRegs_FilePath)
        fboxRegs.addRow(self.names_checkbox_regs)
        fboxRegs.addRow(self.names_create_segments_regs)
        vboxRegs_Buttons = QtWidgets.QHBoxLayout()
        vboxRegs_Buttons.addWidget(self.skip_btn_Regs)
        vboxRegs_Buttons.addWidget(self.import_btn_Regs)
        fboxRegs.addRow(vboxRegs_Buttons) 
        frameHardwareRegs.setLayout(fboxRegs) 

        frameProgress = QtWidgets.QFrame()
        fboxProgress = QtWidgets.QFormLayout()
        fboxProgress.addRow(self.headline_Progress)
        fboxProgress.addRow(self.state_label)
        fboxProgress.addRow(self.pbar)
        frameProgress.setLayout(fboxProgress) 

        #adding some lines to split each part of the gui
        line = QtWidgets.QFrame()
        line.setFrameShape(QtWidgets.QFrame.HLine)
        line.setFrameShadow(QtWidgets.QFrame.Sunken)

        layout.addRow(frameElf)
        layout.addRow(line)
        layout.addRow(frameDB)
        layout.addRow(line)
        layout.addRow(frameHardwareRegs)
        layout.addRow(line)
        layout.addRow(frameProgress)
        
        #connect buttons
        self.selectFile_btn_elf.clicked.connect(self.get_file_elf)
        self.import_btn_elf.clicked.connect(self.start_import_elf)
        self.skip_btn_elf.clicked.connect(self.enable_signature_import)
        self.userdefined_csv_btn_elf.clicked.connect(self.open_userdefined_import_gui)

        self.selectFile_btn_database.clicked.connect(self.get_file_database)
        self.getMultiplefiles_Database_to_List.clicked.connect(self.get_multiple_files_database)
        self.import_btn_database.clicked.connect(self.start_import_database)
        self.skip_btn_database.clicked.connect(self.enable_hardwareregister_import)

        self.selectFile_btn_Regs.clicked.connect(self.get_file_hardwareregister)
        self.import_btn_Regs.clicked.connect(self.start_import_hardwareregister)
        self.skip_btn_Regs.clicked.connect(self.skip_import_hardwareregister)

        #set default Options
        self.overwrite_names_elf_checkbox.setChecked(True)
        self.import_functions_checkbox.setChecked(True)
        self.import_globals_checkbox.setChecked(True)
        self.adjust_for_arm_thumb_checkbox.setChecked(True)
        self.names_checkbox_regs.setChecked(True)
        self.import_sections_checkbox.setChecked(True)

        #setLayout and enable FunctionImport
        self.parent.setLayout(layout)
        self.enable_function_import()
        self.pbar.setEnabled(False)
       
    def open_userdefined_import_gui(self):

        self.UserDefdialog = QtWidgets.QDialog()
        layout = QtWidgets.QFormLayout()

        delimiter_label = QtWidgets.QLabel("Delimiter")        
        function_label = QtWidgets.QLabel("Identifier function")        
        Global_label = QtWidgets.QLabel("Identifier global")        
        name_label = QtWidgets.QLabel("Column name")        
        address_label = QtWidgets.QLabel("Column address")        
        type_label = QtWidgets.QLabel("Column type")        
        size_label = QtWidgets.QLabel("Column size")        
        import_btn = QtWidgets.QPushButton("Import")

        self.delimiter_line = QtWidgets.QLineEdit(";")
        self.function_line = QtWidgets.QLineEdit("FUNC")
        self.global_line = QtWidgets.QLineEdit("Data")
        self.name_line = QtWidgets.QLineEdit("0")
        self.address_line = QtWidgets.QLineEdit("1")
        self.type_line = QtWidgets.QLineEdit("2")
        self.size_line = QtWidgets.QLineEdit("3")
       
        frameElf = QtWidgets.QFrame()
        fBox_Frame = QtWidgets.QFormLayout()
        fBox_Frame.addRow(delimiter_label,self.delimiter_line)
        fBox_Frame.addRow(function_label,self.function_line)
        fBox_Frame.addRow(Global_label,self.global_line)
        fBox_Frame.addRow(name_label,self.name_line)
        fBox_Frame.addRow(address_label,self.address_line)
        fBox_Frame.addRow(type_label,self.type_line)
        fBox_Frame.addRow(size_label,self.size_line)
        fBox_Frame.addRow(import_btn)    
        frameElf.setLayout(fBox_Frame) 
        layout.addRow(frameElf)
       
        import_btn.clicked.connect(self.click_on_import_userdefined_csv)        
        
        self.UserDefdialog.setLayout(layout)
        self.UserDefdialog.setWindowTitle("Define csv style")
        self.UserDefdialog.exec_()

    def start_import_elf(self):
        importPath = self.pathline_Elf.text()
        overwrite_names = self.overwrite_names_elf_checkbox.isChecked()
        import_functions = self.import_functions_checkbox.isChecked()
        import_objects = self.import_globals_checkbox.isChecked()
        import_sections = self.import_sections_checkbox.isChecked()
        offset = 0
        if self.adjust_for_arm_thumb_checkbox.isChecked():
            offset = -1

        Controller.import_file(self,importPath,import_functions,import_objects,import_sections,overwrite_names,offset)

        self.enable_signature_import()
        

    def click_on_import_userdefined_csv(self):
        self.UserDefdialog.close()

        importPath = self.pathline_Elf.text()
        overwrite_names = self.overwrite_names_elf_checkbox.isChecked()
        import_functions = self.import_functions_checkbox.isChecked()
        import_objects = self.import_globals_checkbox.isChecked()
        delimiter = self.delimiter_line.text()
        IdentFunc = self.function_line.text()
        IdentData = self.global_line.text()
        NameCol = self.name_line.text()
        addrCol = self.address_line.text()
        typeCol = self.type_line.text()
        SizeCol = self.size_line.text()        

        offset = 0
        if self.adjust_for_arm_thumb_checkbox.isChecked():
            offset = -1

        Controller.import_userdefined_csv(self,importPath,import_functions,import_objects,overwrite_names,offset,delimiter,IdentFunc,IdentData,NameCol,addrCol,typeCol,SizeCol)

        self.enable_signature_import()


    def start_import_database(self):
        referencePath = self.pathline_database.text()
        additionalPaths = []
        for index in range(self.list_DB.count()):
            additionalPaths.append(self.list_DB.item(index).text())

        self.pbar.setEnabled(True)
        Controller.import_database(self,referencePath,additionalPaths)

        self.enable_hardwareregister_import()
  
    def start_import_hardwareregister(self):
        filePath = self.pathline_Regs.text()
        overwrite_names = self.names_checkbox_regs.isChecked()
        create_segments = self.names_create_segments_regs.isChecked()
        Controller.import_hardware_regs(overwrite_names,filePath,create_segments)
        self.Close(4)

    def get_file_elf(self):
        fname = QtWidgets.QFileDialog.getOpenFileName()
        self.pathline_Elf.insert(fname[0])

    def get_file_database(self):
        fname = QtWidgets.QFileDialog.getOpenFileName()
        self.pathline_database.insert(fname[0])

    def get_file_hardwareregister(self):
        fname = QtWidgets.QFileDialog.getOpenFileName()
        self.pathline_Regs.insert(fname[0])

    def get_multiple_files_database(self):        
        file_name = QtWidgets.QFileDialog()
        file_name.setFileMode(QtWidgets.QFileDialog.ExistingFiles)
        fname = file_name.getOpenFileNames()[0]

        if not isinstance(fname, list):
            self.list_DB.addItem(fname)
        else:
            for files in fname:
                self.list_DB.addItem(files)

    def skip_import_hardwareregister(self):
        self.Close(4)

    def set_progress(self, i):
        self.pbar.setValue(i)  

    def set_state(self, i):
        self.state_label.setText(i)   

    def enable_function_import(self):
        self.set_enable_function_import(True)  
        self.set_enable_signature_import(False) 
        self.set_enable_hardwareregister_import(False)
        self.set_progress(0)

    def enable_signature_import(self):
        self.set_enable_function_import(False)  
        self.set_enable_signature_import(True) 
        self.set_enable_hardwareregister_import(False)
        self.set_progress(0)

    def enable_hardwareregister_import(self):
        self.set_enable_function_import(False)
        self.set_enable_signature_import(False)
        self.set_enable_hardwareregister_import(True)
        self.set_progress(0)

    def set_enable_function_import(self, value):
        self.headline_elf.setEnabled(value)
        self.selectFile_btn_elf.setEnabled(value)
        self.import_btn_elf.setEnabled(value)
        self.skip_btn_elf.setEnabled(value)
        self.overwrite_names_elf_checkbox.setEnabled(value)
        self.pathline_Elf.setEnabled(value)
        self.import_functions_checkbox.setEnabled(value)
        self.import_globals_checkbox.setEnabled(value)
        self.import_sections_checkbox.setEnabled(value)
        self.adjust_for_arm_thumb_checkbox.setEnabled(value)
        self.userdefined_csv_btn_elf.setEnabled(value)

    def set_enable_signature_import(self, value):
        self.selectFile_btn_database.setEnabled(value)
        self.import_btn_database.setEnabled(value)
        self.skip_btn_database.setEnabled(value)
        self.pathline_database.setEnabled(value)
        self.label_refDB.setEnabled(value)
        self.label_add_database.setEnabled(value)
        self.list_DB.setEnabled(value)
        self.getMultiplefiles_Database_to_List.setEnabled(value)

    def set_enable_hardwareregister_import(self, value):
        self.headline_Regs.setEnabled(value)
        self.selectFile_btn_Regs.setEnabled(value)
        self.import_btn_Regs.setEnabled(value)
        self.skip_btn_Regs.setEnabled(value)
        self.names_checkbox_regs.setEnabled(value)
        self.pathline_Regs.setEnabled(value)
        self.names_create_segments_regs.setEnabled(value)





