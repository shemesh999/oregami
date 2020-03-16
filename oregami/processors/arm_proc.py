import sark
import re
import idautils
import idaapi

# To know if we are in a 64bit architecture, compare bad address, to 64bit -1
__EA64__ = idaapi.BADADDR == 0xFFFFFFFFFFFFFFFF

# Need to load reg_utils from upper dir. Different behavior if we are a part of
#   a package (ie. it was installed with the 'setup.py')
# or used directly as plugin or script.
if __package__ is None:
    import sys
    from os import path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
    from reg_utils import *
else:
    from ..reg_utils import *


class ArmProcessor(Processor):
    def __init__(self):
        super(ArmProcessor, self).__init__()
        if __EA64__:
            self._op_details_l = dict()
            self._op_details_l[('ADD', 3)] = ([1, 2], [0])
            self._op_details_l[('SUB', 3)] = ([1, 2], [0])
            self._op_details_l[('ORR', 3)] = ([1, 2], [0])
            self._op_details_l[('AND', 3)] = ([1, 2], [0])
            self._op_details_l[('NEG', 2)] = ([1], [0])
            self._op_details_l[('MVN', 2)] = ([1], [0])
            self._op_details_l[('CMN', 2)] = ([], [0, 1])
            self._op_details_l[('MOVK', 2)] = ([0], [0])
            self._op_details_l[('TBZ', 3)] = ([0], [])
            self._op_details_l[('TBNZ', 3)] = ([0], [])
        else:
            self._op_details_l = dict()
            self._op_details_l[('MOVT', 2)] = ([0], [0])
            self._op_details_l[('ADD', 3)] = ([1, 2], [0])
            self._op_details_l[('ADD', 2)] = ([0, 1], [0])
            self._op_details_l[('POP', 1)] = ([], [0])
            self._op_details_l[('LDM', 2)] = ([0], [1])

        if __EA64__:
            self.ret_regs = []
            self.ret_regs += ['X%d' % x for x in range(0, 1+1)]
            self.ret_regs += ['W%d' % x for x in range(0, 1+1)]
        else:
            self.ret_regs = []
            self.ret_regs += ['R%d' % x for x in range(0, 1+1)]

        if __EA64__:
            self.param_regs = []
            self.param_regs += ['X%d' % x for x in range(0, 4+1)]
            self.param_regs += ['W%d' % x for x in range(0, 4+1)]
        else:
            self.param_regs = []
            self.param_regs += ['R%d' % x for x in range(0, 4+1)]

        self.call_funcs = ['B', 'BL']

    def get_reg_list(self):
        if __EA64__:
            # ARM64 doesnt include registers like W0 and such here. We will
            #   add this manually
            reglist = list(idautils.GetRegisterList())
            for i in range(31):
                reglist += ['W%d' % i]

            return reglist
        else:
            return idautils.GetRegisterList()

    # Some processors have two regs which "include" one another. Such as
    #   X2 (64bit) that includes W2 (32bit)
    # This function expands to the set of all affected regs
    def reg_expand(self, ea, reg_set):
        if __EA64__:
            reg_list = list(reg_set)
            reg_list_expanded = []
            for reg in reg_list:
                m = re.match('[WX]([0-9]+)', reg)
                if m:
                    xnum = int(m.group(1))
                    reg_list_expanded += ['X%d' % xnum]
                    reg_list_expanded += ['W%d' % xnum]

                elif reg == 'WZR':
                    reg_list_expanded += ['XZR']
                    reg_list_expanded += [reg]
                else:
                    reg_list_expanded += [reg]

                # TODO: Add support for S0=D0=Q0. See:
                # http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0473k/dom1359731186885.html
            return set(reg_list_expanded)
        else:
            return reg_set

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

        r_reg2idx = dict()
        r_reg2idx['LR'] = 14
        r_reg2idx['SP'] = 13
        r_reg2idx['PC'] = 15
        for i in range(12+1):
            r_reg2idx['R%d' % i] = i

        d_reg2idx = dict()
        for i in range(31+1):
            d_reg2idx['D%d' % i] = i
        
        r_idx2reg = {}
        for k in r_reg2idx.keys():
            r_idx2reg[r_reg2idx[k]] = k

        d_idx2reg = {}
        for k in d_reg2idx.keys():
            d_idx2reg[d_reg2idx[k]] = k

        opnd = sark.Line(ea).insn.operands[operand_idx]

        # can't be sure that sark got all regs - for example,
        #   'ld16.bu d0, [a12]' doens't recognise a12
        all_regs = self.get_reg_list()

        operand_res = []
        # R0
        operand_res += [(r'^([^,\[\]]+)$', UsageBits.OP_UK)]
        # LR!
        operand_res += [(r'^([^,\[\]]+)\!$', UsageBits.OP_RW)]
        # [R0]
        operand_res += [(r'^\[([^,\[\]]+)\]$', UsageBits.OP_RD)]
        # [R0,#0x20]
        operand_res += [(r'^\[([^,\[\]]+),.*\]$', UsageBits.OP_RD)]
        # R0,LSR#2
        operand_res += [(r'^([^,\[\]]+),LS[RL]#[0-9]+$', UsageBits.OP_RD)]
        # [r12, 5]!
        operand_res += [(r'\[([^,]+)\,.*\]\!', UsageBits.OP_RW)]
        # [R0],#0x54
        operand_res += [(r'\[([^,]+)\],#.+$', UsageBits.OP_RW)]

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

        # handle difficult operands
        operand_re = r'^\{([^,-]+([,-][^,-]+)+)\}$'      # {R4-R8,LR}
        op_bits = UsageBits.OP_UK
        m = re.match(operand_re, opnd.text)
        canon_list = self.get_reg_list()
        if m is not None:
            reg_set = set()
            reg_explicit_set = set()
            elem_list = m.group(1)
            for r in elem_list.split(','):
                # Not a range
                if '-' not in r:
                    e_reg = RegName(ea, canon_list).canon(r)
                    if e_reg is not None:
                        reg_set |= {e_reg}
                        reg_explicit_set |= {e_reg}
                # Is a range
                else:
                    s, e = r.split('-')

                    s = RegName(ea, canon_list).canon(s)
                    e = RegName(ea, canon_list).canon(e)

                    if (s is not None) and (e is not None):
                        if (s in r_reg2idx) and (e in r_reg2idx):
                            reg_explicit_set |= {s}
                            reg_explicit_set |= {e}
                            s_i = r_reg2idx[s]
                            e_i = r_reg2idx[e]
                            for i in range(s_i, e_i+1):
                                reg_set |= {r_idx2reg[i]}
                        elif (s in d_reg2idx) and (e in d_reg2idx):
                            reg_explicit_set |= {s}
                            reg_explicit_set |= {e}
                            s_i = d_reg2idx[s]
                            e_i = d_reg2idx[e]
                            for i in range(s_i, e_i+1):
                                reg_set |= {d_idx2reg[i]}
                        else:
                            logger.error('range with unknown - {}'.format(r))

            for reg in reg_set:
                if reg in reg_explicit_set:
                    iorb.set_usage_bits(reg, operand_idx, op_bits | UsageBits.USAGE_EXPLICIT)
                else:
                    iorb.set_usage_bits(reg, operand_idx, op_bits | UsageBits.USAGE_IMPLICIT_RANGE)

            for reg in (self.reg_expand(ea, reg_set) ^ reg_set):
                iorb.set_usage_bits(reg, operand_idx, op_bits | UsageBits.USAGE_IMPLICIT_COMPOSITE)

            return iorb

        return iorb
