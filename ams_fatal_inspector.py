# -*- coding: utf-8 -*-
import re
import idc
import idaapi
from PyQt5 import QtCore, QtGui, QtWidgets
import sip


def process_stack_trace(log):
    start_addr = int(re.findall(r"Start Address:\s+((?:\d|[a-f]){16})", log)[0], 16)
    ret_addr_list = map(lambda x: int(x, 16) - start_addr, re.findall(r"ReturnAddress\[\d{2}\]:\s+((?:\d|[a-f]){16})", log))

    return [0x7100000000 + addr - 4 for addr in ret_addr_list if addr > 0]


class FileBrowseWidget(QtWidgets.QWidget):
    value_changed = QtCore.pyqtSignal(str)

    def __init__(self):
        super(FileBrowseWidget, self).__init__()
        self.file_txt = QtWidgets.QLineEdit()
        self.file_txt.setReadOnly(True)

        browse_button = QtWidgets.QPushButton("Browse...")
        browse_button.clicked.connect(self.on_click)

        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.file_txt)
        layout.addWidget(browse_button)

    def on_click(self):
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open Atmosphère fatal report", filter="*.log")
        if filename:
            self.file_txt.setText(filename)
            self.value_changed.emit(filename)


class AmsFatalInspectorGui(idaapi.PluginForm):

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        browse_widget = FileBrowseWidget()
        browse_widget.value_changed.connect(self.load_crash_report)

        font = QtGui.QFont()
        font.setFamily("monospace")
        font.setFixedPitch(True)

        self.log_txt = QtWidgets.QTextEdit()
        self.log_txt.setFixedHeight(90)
        self.log_txt.setText("No fatal report loaded")
        self.log_txt.setReadOnly(True)
        self.log_txt.setFont(font)
        self.log_txt.setEnabled(False)

        self.stack_trace_table = QtWidgets.QTableWidget()
        self.stack_trace_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.stack_trace_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.stack_trace_table.horizontalHeader().setStretchLastSection(True)
        self.stack_trace_table.setFont(font)
        self.stack_trace_table.setColumnCount(2)
        self.stack_trace_table.setColumnWidth(0, 150)
        self.stack_trace_table.setHorizontalHeaderLabels(["Address", "Function"])
        self.stack_trace_table.itemDoubleClicked.connect(self.on_stack_address_click)
        self.stack_trace_table.setEnabled(False)

        main_layout = QtWidgets.QVBoxLayout()
        main_layout.addWidget(browse_widget)
        main_layout.addWidget(self.log_txt)
        main_layout.addWidget(self.stack_trace_table)

        self.parent.setLayout(main_layout)

    def OnClose(self, form):
        pass

    def load_crash_report(self, log_file):
        with open(log_file, 'r') as f:
            log = f.read()

        traceback = process_stack_trace(log)

        self.log_txt.setText(log)

        self.stack_trace_table.clear()
        self.stack_trace_table.setHorizontalHeaderLabels(["Address", "Function"])
        self.stack_trace_table.setRowCount(len(traceback))
        for i, addr in enumerate(traceback):
            func_name = idc.GetFunctionName(addr)
            func_name_demangled = idc.Demangle(func_name, idc.GetLongPrm(idc.INF_SHORT_DN))
            if func_name_demangled is not None:
                func_name = func_name_demangled
            self.stack_trace_table.setRowHeight(i, 20)
            self.stack_trace_table.setItem(i, 0, QtWidgets.QTableWidgetItem("0x{:016x}".format(addr)))
            self.stack_trace_table.setItem(i, 1, QtWidgets.QTableWidgetItem(func_name))

        self.log_txt.setEnabled(True)
        self.stack_trace_table.setEnabled(True)

    def on_stack_address_click(self, item):
        addr = int(self.stack_trace_table.item(item.row(), 0).text(), 16)
        idaapi.jumpto(addr)


class AmsFatalInspector(idaapi.plugin_t):
    flags = 0
    wanted_name = "Atmosphère fatal report inspector"
    wanted_hotkey = "Ctrl+Alt+A"
    comment = "Load an Atmosphère fatal report for easy navigation between traceback addresses"
    help = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def term(self):
        pass

    def run(self, arg):
        gui = AmsFatalInspectorGui()
        gui.Show("Atmosphère fatal report inspector")


def PLUGIN_ENTRY():
    return AmsFatalInspector()
