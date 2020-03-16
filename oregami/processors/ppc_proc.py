import sark
import re
import idautils
import idaapi
import logging
logging.basicConfig(level=logging.DEBUG)

# Need to load reg_utils from upper dir. Different behavior if we are a part of
#   a package (ie. it was installed with the 'setup.py')a
# or used directly as plugin or script.
if __package__ is None:
    import sys
    from os import path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
    from reg_utils import *
else:
    from ..reg_utils import *


class PpcProcessor(Processor):
    def __init__(self):
        super(PpcProcessor, self).__init__()
        self._op_details_l = dict()
        # self._op_details_l[('li',2)] = ([],[0])       # se_li r6, 0

        # e_cmpi    cr0, r4, -1
        self._op_details_l[('cmpi', 3)] = ([1], [])
        # se_cmpi   r4, 0
        self._op_details_l[('cmpi', 2)] = ([0], [])
        self._op_details_l[('mtctr', 1)] = ([0], [])
        self._op_details_l[('mtlr', 1)] = ([0], [])
        # e_addi    r8, r4, 0x1E
        self._op_details_l[('addi', 3)] = ([1], [0])
        # se_addi   r1, 0x10
        self._op_details_l[('addi', 2)] = ([0], [0])
        # se_add    r5, r0
        self._op_details_l[('add', 2)] = ([0, 1], [0])
        # add       r4, r7, r8
        self._op_details_l[('add', 3)] = ([1, 2], [0])
        self._op_details_l[('subi', 3)] = ([1], [0])
        self._op_details_l[('subi', 2)] = ([0], [0])
        self._op_details_l[('subf', 2)] = ([0, 1], [0])
        # e_slwi    r6, r5, 2
        self._op_details_l[('slwi', 3)] = ([1], [0])
        # se_slwi   r5, 4
        self._op_details_l[('slwi', 2)] = ([0], [0])
        self._op_details_l[('srwi', 3)] = ([1], [0])
        self._op_details_l[('srwi', 2)] = ([0], [0])
        # se_cmpl r30, r0
        self._op_details_l[('cmpl', 2)] = ([0, 1], [])
        self._op_details_l[('cmpl', 3)] = ([1], [])
        # se_cmpli r27, 4
        self._op_details_l[('cmpli', 2)] = ([0], [])
        # e_cmpli   cr0, r31, 0xA0000000
        self._op_details_l[('cmpli', 3)] = ([1], [])

        self.ret_regs = ['r3', 'r4']
        self.param_regs = ['r%d' % i for i in range(3, 10+1)]
        self.call_funcs = ['b']

    def get_reg_list(self):
        # Some operations actually use lr as an argument and register, even
        #   though it isn't shown in the op itself
        reglist = list(idautils.GetRegisterList())
        reglist += ['lr']
        return reglist

    def get_regs_in_operand(self, ea, operand_idx):
        iorb = InsnOpndRegBits()

        opnd = sark.Line(ea).insn.operands[operand_idx]

        # can't be sure that sark got all regs - for example,
        #   'ld16.bu d0, [a12]' doens't recognise a12
        # from idautils import GetRegisterList
        # all_regs = GetRegisterList()
        all_regs = self.get_reg_list()

        operand_res = []
        # 'r9'
        operand_res += [(r'^([^,\[\]]+)$', UsageBits.OP_UK)]
        # 'f3, f4' - first one
        operand_res += [(r'^([^,\[\]]+)\,(?:[^,\[\]]+)$', UsageBits.OP_UK)]
        # 'f3, f4' - second one
        operand_res += [(r'^(?:[^,\[\]]+)\,([^,\[\]]+)$', UsageBits.OP_UK)]
        # '0(r9)'
        operand_res += [(r'^.*\(([^,\[\]]+)\)$', UsageBits.OP_RD)]

        for operand_re, op_bits in operand_res:
            m = re.match(operand_re, opnd.text)
            if m is None:
                continue

            reg_set = set()
            e_reg = m.group(1)
            e_reg = RegName(ea, all_regs).canon(e_reg)

            if e_reg is not None:
                reg_set |= {e_reg}
            # Didn't recognise any such reg. Probably false positive. Try next
            else:
                continue

            for reg in reg_set:
                iorb.set_usage_bits(reg, operand_idx, op_bits | UsageBits.USAGE_EXPLICIT)

            for reg in (self.reg_expand(ea, reg_set) ^ reg_set):
                iorb.set_usage_bits(reg, operand_idx, op_bits | UsageBits.USAGE_IMPLICIT_COMPOSITE)

        return iorb

    def get_call_handle(self, ea, reg):
        def add_brk(_ea, _reg, opbits):

            # The register was probably backed up, and will be restored
            #   when returning
            if _reg not in self.ret_regs:
                opbits &= ~UsageBits.OP_WR

            # Even if the function call was determined to be read+write, we
            #   don't want to continue scanning backwards and use this as part
            #   of the 'init stage'.
            # So we will mark this as a break.
            if opbits & UsageBits.OP_WR == UsageBits.OP_WR:
                opbits |= UsageBits.OP_BRK

            return opbits

        mnem = sark.Line(ea).insn.mnem

        if (mnem in self.call_funcs) and (reg in self.param_regs):
            return Processor.FUNC_SCAN, add_brk

        return Processor.FUNC_NONE, None
