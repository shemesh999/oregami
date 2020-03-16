import ida_nalt
import ida_struct
from oregami.reg_utils import *


def rf_settype(rf, type_name):
    for insn in rf.get_noinit_instructions():
        for opnd in insn.operands:
            if opnd.uf_is_read and (not opnd.uf_is_write) and \
                    (not opnd.uf_is_implicit):
                set_type(insn.ea, opnd.n, type_name)


##################
# Type set logic #
##################

def set_type(ea, opnd_idx, type_name, off=0):
    logger.info("setting type ea={:x}, idx={}, type={}".format(ea, opnd_idx, type_name))
    str_id = ida_struct.get_struc_id(type_name)
    idc.op_stroff(ea, opnd_idx, str_id, off)
    ida_nalt.set_aflags(ea, ida_nalt.get_aflags(ea) | ida_nalt.AFL_ZSTROFF)


def get_type_from_user():
    # without this line, waiting a few seconds for user input will cause the
    #   'Please wait...' msgbox to jump and make the system freeze.
    orig_timeout = idaapi.set_script_timeout(0x7fffffff)

    struct_type = ida_kernwin.choose_struc('Choose type')
    idaapi.set_script_timeout(orig_timeout)

    if struct_type is None:
        return None

    type_name = ida_struct.get_struc_name(struct_type.id)
    return type_name
