from weable.src.analysis import perform_analysis
from weable.src.registry import ClassRegistry
from weable.src.iclass import IClass, BASE_ICLASS
from binaryninja import *


def gui_perform_analysis(bv: BinaryView):
    log_info("Started Weable analysis")
    perform_analysis(bv)


PluginCommand.register(
    "WeAble analysis", 
    "Performs complex analysis on OS* classes for type restoration", 
    gui_perform_analysis
)