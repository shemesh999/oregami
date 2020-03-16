import ida_kernwin
import idc
import idaapi
import logging
import idautils
import string
import importlib
import ida_frame
import ida_funcs
from functools import reduce
from .sark_bc import *


# This class helps configuring the usage of the oregami plugin
class OregamiConf(object):
    def __init__(self):
        format_str = '[%(name)s] <%(module)s:%(funcName)s> ' \
                     '%(levelname)s: %(message)s'
        logging.basicConfig(level=logging.INFO, format=format_str)
        self.logger = logging.getLogger('Oregami')
        self.cache_bool = True
        self._proc_name = None
        self._used_processor = Processor
        self._proc = self._used_processor()

    @property
    def proc(self):
        proc_name = idaapi.get_inf_structure().procName.lower()

        # In case the processor changed - loading an idb after the plugin was already loaded
        if proc_name == self._proc_name:
            return self._proc

        try:
            proc_module = importlib.import_module('oregami.processors.{}_proc'.format(proc_name))
            self._used_processor = getattr(proc_module, '{}Processor'.format(proc_name.capitalize()))
            self._proc = self._used_processor()
            logger.info('Using configuration for {} processor'.format(proc_name))
        except ImportError:
            self._used_processor = Processor
            self._proc = self._used_processor()
            logger.info('Using default processor')

        self._proc_name = proc_name
        return self._proc


class InsnOpndRegBits(object):
    """
    class used for handling the UsageBits of different registers in different
        operand for a certain instruction.
    """

    EMPTY_REG = 'EMPTY'

    def __init__(self, iorb=None):
        self._regs = {}
        self._opnds = {}
        if iorb is not None:
            self.mix(iorb)

    def mix(self, iorb):
        for reg, opnd_idx in iorb.get_reg_opnd_tuples():
            self.set_usage_bits(reg, opnd_idx, iorb.get_usage_bits(reg, opnd_idx))

    def set_usage_bits(self, reg, opnd_idx, usagebits):
        if reg not in self._regs:
            self._regs[reg] = {}
        if opnd_idx not in self._opnds:
            self._opnds[opnd_idx] = {}
        if reg not in self._opnds[opnd_idx]:
            self._opnds[opnd_idx][reg] = 0
        if opnd_idx not in self._regs[reg]:
            self._regs[reg][opnd_idx] = 0

        self._regs[reg][opnd_idx] |= usagebits
        self._opnds[opnd_idx][reg] |= usagebits

    def get_usage_bits(self, reg=None, opnd_idx=None):
        if (reg is not None) and (opnd_idx is not None):
            return self._regs.get(reg, {}).get(opnd_idx, 0)
        elif reg is not None:
            return reduce(lambda x, y: x | y, self._regs.get(reg, {}).values(), 0)
        elif opnd_idx is not None:
            return reduce(lambda x, y: x | y, self._opnds.get(opnd_idx, {}).values(), 0)
        else:
            return reduce(lambda x, y: x | y, [self.get_usage_bits(reg=r) for r in self.get_regs()], 0)

    def get_regs(self, opnd_idx=None):
        if opnd_idx is None:
            return self._regs.keys()

        if opnd_idx not in self._opnds:
            return []

        return self._opnds[opnd_idx].keys()

    def get_opnd_idxs(self, reg=None):
        if reg is None:
            return self._opnds.keys()

        if reg not in self._regs:
            return []

        return self._regs[reg].keys()

    def get_reg_opnd_tuples(self):
        tuple_l = []
        for reg, opnd_d in self._regs.items():
            tuple_l += [(reg, opnd_idx) for opnd_idx in opnd_d.keys()]
        return tuple_l

    def get_masked(self, op_val=0, op_mask=None):
        if op_mask is None:
            op_mask = op_val

        masked_iorb = InsnOpndRegBits()
        for reg, opnd_idx in self.get_reg_opnd_tuples():
            op_bits = self.get_usage_bits(reg, opnd_idx)
            if op_bits & op_mask == op_val:
                masked_iorb.set_usage_bits(reg, opnd_idx, op_bits)

        return masked_iorb


class EnumClass(dict):
    """
    This class can be initialized on an instance of another class, which may contain an internal enumeration.
    The class will return as a back dictionary, allowing to get the enum name by its value
    """
    def __init__(self, instance, pretext=''):
        super(EnumClass, self).__init__()
        num2name = {y: x for x, y in instance.__class__.__dict__.items()
                    if isinstance(y, int) and x.startswith(pretext)}
        self.update(num2name)


class BitField(object):
    def __init__(self, val):
        self.val = val

    def __str__(self):
        # create dictionary of bits to string from local enum
        # take from dictionary only values which are integers, and a power of 2 (so as not to include masks) or zero
        # In case of multiple ids with the same value, the last is taken
        bits2name = {y: x for x, y in self.__class__.__dict__.items()
                     if isinstance(y, int) and ((y & (y-1) == 0) or (y == 0))}

        bitfield_val = self.val
        bitfield_list = list()
        while bitfield_val:
            # math trick to get lowest set bit
            last_bit = ((bitfield_val ^ (bitfield_val - 1)) + 1) >> 1
            bitfield_val &= ~last_bit
            bitfield_list.append(bits2name.get(last_bit, 'NUM_{:x}'.format(last_bit)))

        if (len(bitfield_list) == 0) and (0 in bits2name):
            bitfield_list = [bits2name[0]]

        return '{}({})'.format(self.__class__.__name__, ' | '.join(bitfield_list))


class UsageBits(BitField):
    ########################
    # Usage operation bits #
    ########################

    # unknown. Is 0, so that if we want to add found op, will just OR to it.
    OP_UK = 0
    # no operation. Is also 0, because we will OR with other
    #   elements if there is op.
    OP_NO = 0
    OP_RD = 1
    OP_WR = 2
    # break scan - regardless of r, w, or rw
    OP_BRK = 4

    OP_RW = OP_RD | OP_WR

    OP_MASK = OP_RD | OP_WR | OP_BRK

    ###################
    # Usage type bits #
    ###################

    USAGE_EXPLICIT = 8
    # ie. R1-R8 includes R2
    USAGE_IMPLICIT_RANGE = 0x10
    # ie. change in eax is also a change in al
    USAGE_IMPLICIT_COMPOSITE = 0x20
    # ie. in this 'call' operation, R0 was changed
    USAGE_IMPLICIT_FUNC_CHANGED = 0x40
    # ie. the POP operation changes SP, even though it does not contain
    #   its name (also RET, etc.)
    USAGE_IMPLICIT_UNNAMED = 0x80
    # implicit not contained in previous
    USAGE_IMPLICIT_OTHER = 0x100

    USAGE_IMPLICIT_MASK = USAGE_IMPLICIT_RANGE | USAGE_IMPLICIT_COMPOSITE | \
        USAGE_IMPLICIT_FUNC_CHANGED | USAGE_IMPLICIT_UNNAMED | USAGE_IMPLICIT_OTHER

    USAGE_MASK = USAGE_EXPLICIT | USAGE_IMPLICIT_MASK

    GEN_MASK = OP_MASK | USAGE_MASK

    NO_OPERAND_IDX = -1


class Processor(object):
    """
    This is the main (and default) class handling differences between processors.
    In case some functionality seems to be mistaken for a specific processor (such as not all registers
    are seen when selecting registers, or some opcodes are claiming that a register is written to even though
    it is only read) - then the processor should create a seperate class inheriting from this one, and
    changing what needs to be changed.

    """
    FUNC_NONE = 0
    FUNC_CONST = 1
    FUNC_SCAN = 2

    def __init__(self):
        self._op_details_l = {}

    def get_call_handle(self, ea, reg):
        return Processor.FUNC_NONE, None

    # This function should return all registers that exist (at least, for oregami purposes) in the processor.
    # The default function of IDA does not do its job in some processors.
    def get_reg_list(self):
        return idautils.GetRegisterList()

    # Some processors have two regs which "include" one another. Such as
    #   X2 (64bit) that includes W2 (32bit)
    # This function expands to the set of all affected regs
    def reg_expand(self, ea, reg_set):
        return reg_set

    # Function for getting list of load and store registers - depending on opcode
    # Used mainly for ops such as calls, which tend to change certain regs
    def op_details_regs(self, mnem, operand_num, ea):
        return InsnOpndRegBits()

    # Function for getting list of load and store operands - depending on opcode
    def op_details_idx(self, mnem, operand_num, ea):
        import types
        if (mnem, operand_num) not in self._op_details_l:
            return None, None
        if isinstance(self._op_details_l[(mnem, operand_num)],
                      types.FunctionType):
            return self._op_details_l[(mnem, operand_num)](ea)
        elif isinstance(self._op_details_l[(mnem, operand_num)],
                        tuple):
            return self._op_details_l[(mnem, operand_num)]
        else:
            return None, None

    def get_regs_in_operand(self, ea, operand_idx):
        opnd = sark.Line(ea).insn.operands[operand_idx]

        # can't be sure that sark got all regs - for example,
        #   'ld16.bu d0, [a12]' doens't recognise a12
        all_regs = self.get_reg_list()

        all_user_regs = RegName(ea, all_regs).get_users()
        op_bits = UsageBits.OP_UK

        found_reg_set = set()
        for reg in set(all_user_regs) | set(all_regs):
            if reg in opnd.text:
                # check if before and after the reg name there is some
                #   letter - making the regname only a substring
                s_idx = opnd.text.index(reg)
                e_idx = s_idx + len(reg)

                if s_idx > 0 and opnd.text[s_idx - 1] in \
                        (string.ascii_letters + string.digits + '_'):
                    continue
                if e_idx <= len(opnd.text) - 1 and opnd.text[e_idx] in \
                        (string.ascii_letters + string.digits + '_'):
                    continue

                reg = RegName(ea, all_regs).canon(reg)
                found_reg_set |= {reg}

                break

        iorb = InsnOpndRegBits()
        for reg in found_reg_set:
            iorb.set_usage_bits(reg, operand_idx, op_bits | UsageBits.USAGE_EXPLICIT)

        for reg in (self.reg_expand(ea, found_reg_set) ^ found_reg_set):
            iorb.set_usage_bits(reg, operand_idx, op_bits | UsageBits.USAGE_IMPLICIT_COMPOSITE)

        return iorb


# Chooser for selecting a register - either by canonical name, or user name
class RegChoose(idaapi.Choose):
    def __init__(self, ea, canon_list, title='Choose a reg',
                 icon=54, flags=0, width=None, height=None,
                 embedded=False, modal=False):
        idaapi.Choose.__init__(
            self,
            title,
            [["User", 10], ["Canon", 10]],
            flags=flags,
            width=width,
            height=height,
            embedded=embedded)
        self.canon_list = canon_list
        self.ea = ea
        self.n = 0
        self.items = [self.make_item(x) for x in canon_list]
        self.icon = icon
        self.selcount = 0
        self.modal = modal
        self.popup_names = []
        self.title = title

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show(self.modal) >= 0

    def make_item(self, reg):
        user_name = RegName(self.ea, self.canon_list).user_name(reg)
        return [user_name, reg]

    def OnClose(self):
        return


class RegName(object):
    """
    Class used for converting to the canon or user name in a specific address, as well as renaming registers
        in specific ranges.
    canon_list may be supplied, because IDAs default GetRegisterList sometimes misses some of the registers.
    """
    def __init__(self, ea=None, canon_list=None):
        if canon_list is None:
            canon_list = idautils.GetRegisterList()
        self.canon_list = canon_list
        self.ea = None
        if ea is not None:
            self._create_conversion_tables(ea)

    def _create_conversion_tables(self, ea):
        canon2user = {}
        user2canon = {}

        for canon in self.canon_list:
            regvar = ida_frame.find_regvar(ida_funcs.get_func(ea), ea, canon)
            if regvar:
                user2canon[regvar.user] = canon
                canon2user[canon] = regvar.user

        self.ea = ea
        self.canon2user = canon2user
        self.user2canon = user2canon

    def get_users(self, ea=None):
        if (ea is not None) and ea != self.ea:
            self._create_conversion_tables(ea)

        return self.user2canon.keys()

    # get canon reg_name if exists
    def canon(self, reg, ea=None):
        if (ea is not None) and ea != self.ea:
            self._create_conversion_tables(ea)

        if self.ea is None:
            raise Exception('Tried getting canon register, without supplying address')

        if reg in self.canon_list:
            return reg
        if reg in self.user2canon:
            return self.user2canon[reg]
        return None

    # get user given reg_name if exists
    def user_name(self, reg, ea=None):
        if (ea is not None) and ea != self.ea:
            self._create_conversion_tables(ea)

        if self.ea is None:
            raise Exception('Tried getting canon register, without supplying address')

        if reg in self.canon2user:
            return self.canon2user[reg]
        if reg in self.canon_list:
            return reg
        return None

    # if reg was renamed - get full name
    def full_name(self, reg, ea=None):
        canon_reg = self.canon(reg, ea)
        user_reg = self.user_name(reg, ea)

        if user_reg == canon_reg:  # there was no user renamed register
            return canon_reg

        return '{} {{{}}}'.format(user_reg, canon_reg)

    @staticmethod
    def erase_range(s_ea, e_ea, canon):
        pfn = ida_funcs.get_func(s_ea)

        prev_ranges = []

        # if there was a rename range with this reg containing the start of the
        #   range (s_ea) - remember it
        prev_range_s = ida_frame.find_regvar(pfn, s_ea, canon)
        if (prev_range_s is not None) and (prev_range_s.start_ea < s_ea):
            prev_ranges += [(prev_range_s.start_ea, s_ea, prev_range_s.user)]

        # if there was a rename range with this reg containing the end of the
        #   range (e_ea) - remember it
        prev_range_s = ida_frame.find_regvar(pfn, e_ea, canon)
        if ((prev_range_s is not None) and
                (prev_range_s.start_ea < e_ea) and (prev_range_s.end_ea > e_ea)):
            prev_ranges += [(e_ea, prev_range_s.end_ea, prev_range_s.user)]

        logger.debug('Delete range {:x} : {:x} - {}'.format(s_ea, e_ea, canon))
        # deletion seems to require actual existing range - so we'll change the
        #   name to orig, and then delete it
        idc.define_local_var(s_ea, e_ea, canon, canon)
        idc.refresh_idaview_anyway()
        ida_frame.del_regvar(pfn, s_ea, e_ea, canon)
        idc.refresh_idaview_anyway()

        # restore ranges
        for s_ea, e_ea, reg_new_name in prev_ranges:
            logger.debug('Restore range {:x} : {:x} - {}->{}'.format(s_ea, e_ea, canon, reg_new_name))
            idc.define_local_var(s_ea, e_ea, canon, reg_new_name)
            idc.refresh_idaview_anyway()

    @staticmethod
    def rename_range(s_ea, e_ea, canon, username):
        if (username == canon) or (username == ''):
            RegName.erase_range(s_ea, e_ea, canon)
        else:
            RegName.erase_range(s_ea, e_ea, canon)
            logger.info('Renaming range {:x} : {:x} - {}->{}'.format(s_ea, e_ea, canon, username))
            idc.define_local_var(s_ea, e_ea, canon, username)
            idc.refresh_idaview_anyway()


#####################################
# Sark and IDA fixes and extensions #
#####################################


def is_func(ea):
    try:
        sark.Function(ea)
        return True
    except sark.exceptions.SarkNoFunction:
        return False


# fix regular AskStr, so it doesn't time out
def AskStr(def_val, q_str):
    # without this line, waiting a few seconds for user input will cause the
    #   'Please wait...' msgbox to jump and make the system freeze.
    orig_timeout = idaapi.set_script_timeout(0x7fffffff)
    ret = ida_kernwin.ask_str(def_val, 0, q_str)
    idaapi.set_script_timeout(orig_timeout)
    return ret


#####################
# Reg functionality #
#####################

# get the register that the cursor is on
def get_reg_from_cursor(ea=None, canon_list=None):
    if ea is None:
        ea = idc.get_screen_ea()
        
    if canon_list is None:
        canon_list = idautils.GetRegisterList()

    if 'get_highlight' in dir(ida_kernwin):  # from IDA 7.1
        w = ida_kernwin.get_current_viewer()
        t = ida_kernwin.get_highlight(w)
        reg = None
        if t:
            reg, _ = t
    else:  # in IDA 6.98
        reg = ida_kernwin.get_highlighted_identifier()

    if reg is None:
        return None
    reg = RegName(ea, canon_list).canon(reg)

    if reg in canon_list:
        return reg

    return None


def get_reg_from_user(orig_ea):
    canon_list = conf.proc.get_reg_list()
    reg = get_reg_from_cursor(orig_ea, canon_list)

    if reg is None:
        # Ask for user input - may be used to look for a reg influencing the
        #   line - even if it doesn't exist on the line

        reg_idx = RegChoose(orig_ea, canon_list).Show(True)
        if reg_idx >= 0:
            reg = canon_list[reg_idx]
        else:
            return None

    reg = RegName(orig_ea, canon_list).canon(reg)

    return reg


##############
# call funcs #
##############


def func_get_call_ea(ea):
    func_eas = []
    for xref in sark.Line(ea).xrefs_from:
        # if it is not a code xref, skip
        if xref.iscode == 0:
            continue

        # if it is code, but not a func - hard to parse correctly. Return err.
        if not is_func(xref.to):
            logger.error('< %x > Cannot be sure of things, while there is a '
                         'jump to code that isnt a func (%x)' % (ea, xref.to))
            continue

        # if we reference somewhere outside the func - it is a call
        if sark.Function(xref.to).start_ea != sark.Function(ea).start_ea:
            func_eas += [xref.to]

    num_refs = len(func_eas)
    if num_refs == 0:
        return None
    elif num_refs == 1:
        return func_eas[0]
    else:
        # weird - expected only one xref outside the func.
        logger.error("< %x > Found more than one reference outside the func. "
                     "Isn't supposed to happen." % ea)
        return None


def func_is_call(ea):
    if func_get_call_ea(ea) is None:
        return False
    else:
        return True


conf = OregamiConf()
logger = conf.logger
