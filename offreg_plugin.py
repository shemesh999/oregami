from oregami.reg_utils import *
from oregami.reg_type import rf_settype, get_type_from_user
from oregami.reg_frame import RegFrame
import ida_offset

class OffRegPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "OffReg"
    help = "Set offset for regs in their usage frame - only when " \
           "used as a specific variable"
    wanted_name = "OffReg"
    wanted_hotkey = "Shift+R"

    @staticmethod
    def init():
        return idaapi.PLUGIN_OK

    @staticmethod
    def term():
        pass

    @staticmethod
    def run(arg):
        start, _ = sark.get_selection()

        offreg_plugin_starter(start)


def PLUGIN_ENTRY():
    return OffRegPlugin()


def rf_setoff(rf, off_ea):
    for insn in rf.get_noinit_instructions():
        done_offset = False
        need_offset = False
        for opnd in insn.operands:
            if opnd.uf_is_read and (not opnd.uf_is_write) and \
                    (not opnd.uf_is_implicit):
                need_offset = True
                print('Setting offset {:x} for {:x} operand #{}'.format(off_ea, insn.ea, opnd.n))
                if opnd.type.name == 'Memory_Displacement':
                    ida_offset.op_offset(insn.ea, opnd.n, idc.REFINFO_NOBASE | idc.REF_OFF32, idc.BADADDR, off_ea)
                    done_offset = True
        if need_offset and (not done_offset):
            # probably another operand is an immediate value which needs this to be applied to it. May have false positives
            for opnd in insn.operands:
                if opnd.type.name == 'Immediate_Value':
                    ida_offset.op_offset(insn.ea, opnd.n, idc.REFINFO_NOBASE | idc.REF_OFF32, idc.BADADDR, off_ea)
                    break
                    


def offreg_plugin_starter(orig_ea):
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
    off_ea = ida_kernwin.ask_addr(0, 'Choose offset')
    if off_ea is None:
        return
        
    # global conf
    rf = RegFrame(orig_ea, reg, force=(not conf.cache_bool))
    rf_setoff(rf, off_ea)
