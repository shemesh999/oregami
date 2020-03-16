from oregami.reg_utils import *
from oregami.reg_type import rf_settype, get_type_from_user
from oregami.reg_frame import RegFrame


class TyperegterPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "TypeREGter"
    help = "Set type for regs in their usage frame - only when " \
           "used as a specific variable"
    wanted_name = "TypeREGter"
    wanted_hotkey = "Shift+T"

    @staticmethod
    def init():
        return idaapi.PLUGIN_OK

    @staticmethod
    def term():
        pass

    @staticmethod
    def run(arg):
        start, _ = sark.get_selection()

        typeregter_plugin_starter(start)


def PLUGIN_ENTRY():
    return TyperegterPlugin()


def typeregter_plugin_starter(orig_ea):
    canon_list = conf.proc.get_reg_list()
    # print canon_list
    reg = get_reg_from_cursor(orig_ea, canon_list)

    if reg is None:
        # Ask for user input - may be used to look for a reg influencing
        #   the line - even if it doesn't exist on the line
        reg_idx = RegChoose(orig_ea, canon_list).Show(True)
        if reg_idx >= 0:
            reg = canon_list[reg_idx]
        else:
            return

    reg = RegName(orig_ea, canon_list).canon(reg)

    if reg is None:
        return

    # Get type name
    type_name = get_type_from_user()

    if type_name is None:
        return

    # global conf
    rf = RegFrame(orig_ea, reg, force=(not conf.cache_bool))
    rf_settype(rf, type_name)
