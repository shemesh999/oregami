import sark
import re
import idautils
import idaapi

# To know if we are in a 64bit architecture, compare bad address, to 64bit -1
__EA64__ = idaapi.BADADDR == 0xFFFFFFFFFFFFFFFF

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


class MetapcProcessor(Processor):
    def __init__(self):
        super(MetapcProcessor, self).__init__()
        if __EA64__:
            self._op_details_l = {}
        else:
            self._op_details_l = {}

        if __EA64__:
            self.ret_regs = []
            self.ret_regs += ['rax']
            self.ret_regs += ['xmm0']
        else:
            self.ret_regs = []
            # self.ret_regs += ['R%d' % x for x in range(0,1+1)]

        if __EA64__:
            self.param_regs = []
            self.param_regs += ['rcx', 'rdx', 'r8', 'r9']
            self.param_regs += ['xmm0', 'xmm1', 'xmm2', 'xmm3']
        else:
            self.param_regs = []
            # self.param_regs += ['R%d' % x for x in range(0,4+1)]

        if __EA64__:
            self.saved_regs = []
            self.saved_regs += ['rbx', 'rbp', 'rdi', 'rsi', 'rsp', 'r12',
                                'r13', 'r14', 'r15']
            self.saved_regs += ['xmm%d' % i for i in range(6, 15+1)]
        else:
            self.saved_regs = []
            # self.param_regs += ['R%d' % x for x in range(0,4+1)]

        # self.call_funcs = ['B', 'BL']
        self.call_funcs = []

    def get_reg_list(self):
        reglist = list(idautils.GetRegisterList())
        for base_reg in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'sp', 'bp']:
            reglist += ['e{}'.format(base_reg)]
            if __EA64__:
                reglist += ['r{}'.format(base_reg)]
            # ARM64 doesnt include registers like W0 and such here. We will
            #   add this manually

        return reglist

    # Some processors have two regs which "include" one another. Such as
    #   X2 (64bit) that includes W2 (32bit)
    # This function expands to the set of all affected regs
    def reg_expand(self, ea, reg_set):
        reg_list = list(reg_set)
        reg_list_expanded = []
        for reg in reg_list:
            reg_list_expanded += [reg]
            for base_reg in ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'sp', 'bp']:
                if base_reg.endswith(reg):
                    reg_list_expanded += [base_reg]
                    reg_list_expanded += ['e{}'.format(base_reg)]
                    if __EA64__:
                        reg_list_expanded += ['r{}'.format(base_reg)]

        return set(reg_list_expanded)

    def get_call_handle(self, ea, reg):
        def add_brk(_ea, _reg, opbits):

            # The register was probably backed up, and will be restored
            #   when returning
            if _reg not in self.ret_regs:
                opbits &= ~UsageBits.OP_WR

            # Even if the function call was determined to be read+write, we
            #   don't want to continue scanning backwards and use this as
            #   part of the 'init stage'.
            # So we will mark this as a break.
            if opbits & UsageBits.OP_WR == UsageBits.OP_WR:
                opbits |= UsageBits.OP_BRK

            return opbits

        mnem = sark.Line(ea).insn.mnem
        if (mnem in self.call_funcs) and (reg in self.param_regs):
            return Processor.FUNC_SCAN, add_brk

        return Processor.FUNC_NONE, None

    def get_regs_in_operand(self, ea, operand_idx):
        iorb = InsnOpndRegBits()

        opnd = sark.Line(ea).insn.operands[operand_idx]

        # can't be sure that sark got all regs - for example,
        #   'ld16.bu d0, [a12]' doens't recognise a12
        # from idautils import GetRegisterList
        # all_regs = GetRegisterList()
        all_regs = self.get_reg_list()

        operand_res = []
        # ebx
        operand_res += [(r'^([^,\[\]]+)$', UsageBits.OP_UK)]
        # qword ptr [ecx*4+2+var10]
        operand_res += [(r'^.*\[(.+)(?:\+.*|\-.*|\*.*|)\]$', UsageBits.OP_RD)]
        # qword ptr [ebx+ecx*4+2+var10]
        operand_res += [(r'^.*\[.+\+(.+)(?:\+.*|\-.*|\*.*|)\]$',
                        UsageBits.OP_RD)]

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

        return iorb
