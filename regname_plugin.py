import idaapi
import sark
from oregami.reg_frame import RegFrame
from oregami.reg_utils import conf, get_reg_from_user
from oregami.reg_name import rf_rename, get_name_from_user


def regname_plugin_starter(ea):
    # Get register
    reg = get_reg_from_user(ea)

    if reg is None:
        return

    # Get new name
    reg_new_name = get_name_from_user(ea, reg)

    if reg_new_name is None:
        return

    # global conf
    rf = RegFrame(ea, reg, force=(not conf.cache_bool))
    rf_rename(rf, reg_new_name)


class RegnamePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "reGname"
    help = "Rename registers in their usage frame - only when used " \
           "as a specific variable"
    wanted_name = "reGname"
    wanted_hotkey = "Shift+N"

    @staticmethod
    def init():
        return idaapi.PLUGIN_OK

    @staticmethod
    def term():
        pass

    @staticmethod
    def run(arg):
        start, _ = sark.get_selection()

        regname_plugin_starter(start)


def PLUGIN_ENTRY():
    return RegnamePlugin()
