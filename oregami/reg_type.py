import ida_nalt
from oregami.ida_compat import compat_get_struc_id, compat_get_struc_name, compat_choose_struc
from oregami.reg_utils import *


def rf_settype(rf, type_name):
    for insn in rf.get_noinit_instructions():
        done_offset = False
        need_offset = False
        for opnd in insn.operands:
            if opnd.uf_is_read and (not opnd.uf_is_write) and \
                    (not opnd.uf_is_implicit):
                need_offset = True
                if opnd.type.name == 'Memory_Displacement':
                    set_type(insn.ea, opnd.n, type_name)
                    done_offset = True
        if need_offset and (not done_offset):
            # probably another operand is an immediate value which needs this to be applied to it.
            # May have false positives
            for opnd in insn.operands:
                if opnd.type.name == 'Immediate_Value':
                    set_type(insn.ea, opnd.n, type_name)
                    break


##################
# Type set logic #
##################

def set_type(ea, opnd_idx, type_name, off=0):
    logger.info("setting type ea={:x}, idx={}, type={}".format(ea, opnd_idx, type_name))
    str_id = compat_get_struc_id(type_name)
    idc.op_stroff(ea, opnd_idx, str_id, off)
    ida_nalt.set_aflags(ea, ida_nalt.get_aflags(ea) | ida_nalt.AFL_ZSTROFF)


def get_type_from_user():
    # without this line, waiting a few seconds for user input will cause the
    #   'Please wait...' msgbox to jump and make the system freeze.
    orig_timeout = idaapi.set_script_timeout(0x7fffffff)

    struct_tid = compat_choose_struc('Choose type')
    idaapi.set_script_timeout(orig_timeout)

    if struct_tid is None:
        return None

    type_name = compat_get_struc_name(struct_tid)
    return type_name
