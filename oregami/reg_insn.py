from .reg_utils import *

# TODOS:
# - Add special handling which returns actual regs - Done.
# - Maybe add caching also to lines and instructions
# - Use IDAs is_call_insn

class RegOperand(sark.code.instruction.Operand):
    """
    A class used to represent an operand of an instruction, using both
        IDA api and textual analysis to understand the effected and used
        registers.
    This class inherits from the sark operand, and as such will be inited
        the same way.
    """
    ANALYZE_STR = 1
    ANALYZE_API = 2
    ANALYZE_BOTH = ANALYZE_STR | ANALYZE_API

    def __init__(self, *l_args, **d_args):
        # If named param for sark_operand exists, copy params internally
        if 'sark_operand' in d_args:
            self.__dict__.update(d_args['sark_operand'].__dict__)
        else:
            super(RegOperand, self).__init__(*l_args, **d_args)

        self._iorb_text = self._analyze_text()
        self._iorb_api = self._analyze_api()
        self._iorb = self._analyze()

        # replace properties with our own
        self._regs = set(self._iorb.get_regs())

        # Notice - in general, different regs may have different usages
        op_bits = self._iorb.get_usage_bits()
        self._read = (op_bits & UsageBits.OP_RD == UsageBits.OP_RD)
        self._write = (op_bits & UsageBits.OP_WR == UsageBits.OP_WR)

    @property
    def regs(self):
        return self.get_regs()

    def get_regs(self, op_val=0, op_mask=None):
        return self._iorb.get_masked(op_val=op_val, op_mask=op_mask).get_regs()

    def _analyze_text(self):
        # global conf
        return conf.proc.get_regs_in_operand(self._ea, self.n)

    def _analyze_api(self):
        op_bits = 0

        if self.is_read:
            if self.type.is_reg:
                op_bits |= UsageBits.OP_RD
            elif self.type.is_displ:
                op_bits |= UsageBits.OP_RD

        if self.is_write:
            # a write to [a4]4 is actually a read of a4
            if self.type.is_reg:
                op_bits |= UsageBits.OP_WR
            elif self.type.is_displ:
                op_bits |= UsageBits.OP_RD

        # reg_set = self.regs
        reg_set = super(RegOperand, self).regs
        if len(reg_set) == 0:
            reg_set.add(InsnOpndRegBits.EMPTY_REG)

        reg_set = conf.proc.reg_expand(self._ea, reg_set)

        iorb = InsnOpndRegBits()
        if op_bits == 0:
            return iorb

        for reg in reg_set:
            iorb.set_usage_bits(reg, self.n, op_bits)

        return iorb

    # Analyze the combined information from both text and API
    def _analyze(self):
        iorb = InsnOpndRegBits()
        if self._iorb_text is None:
            self._iorb_text = self._analyze_text()

        iorb.mix(self._iorb_text)

        if self._iorb_api is None:
            self._iorb_api = self._analyze_api()

        iorb.mix(self._iorb_api)

        # If couldn't recognize reg name - take reg from text
        if InsnOpndRegBits.EMPTY_REG in iorb.get_regs():
            iorb = InsnOpndRegBits()
            op_bits = self._iorb_api.get_usage_bits(reg=InsnOpndRegBits.EMPTY_REG, opnd_idx=self.n)
            for reg, opnd_idx in iorb.get_reg_opnd_tuples():
                if reg is InsnOpndRegBits.EMPTY_REG:
                    continue
                iorb.set_usage_bits(reg, opnd_idx, iorb.get_usage_bits(reg, opnd_idx))
            for reg in self._iorb_text.get_regs():
                iorb.set_usage_bits(reg, self.n, op_bits)

        return iorb

    # Return InsnOpndRegBits with information of regs, and their determined usage bits
    # (or UsageBits.OP_UK if the reg is used, but unclear what usage it is)
    # In case of unrecognised register, will use the dictionary key EMPTY_REG
    # Params:
    # source - accepts the following values:
    #    ANALYZE_STR - meaning the analyze of the operand string
    #    ANALYZE_API - meaning internal flags
    #    ANALYZE_BOTH - the combined data from both STR and IDA
    def get_iorb_for_source(self, source=ANALYZE_BOTH):
        if source == RegOperand.ANALYZE_STR:
            return self._iorb_text

        elif source == RegOperand.ANALYZE_API:
            return self._iorb_api

        elif source == RegOperand.ANALYZE_BOTH:
            return self._iorb

    def __repr__(self):
        s_l = []
        s_l += ['<Operand(ea={:x}, n={}, text={})>'.format(self._ea, self.n, self.text)]
        if self._iorb_text is not None:
            s_l += ['\tText Analysis - {{{}}}'.format
                    (','.join(['"{}"-{}'.format(r, UsageBits(self._iorb_text.get_usage_bits(reg=r)))
                               for r in self._iorb_text.get_regs()]))]
        if self._iorb_api is not None:
            s_l += ['\tApi Analysis - {{{}}}'.format
                    (','.join(['"{}"-{}'.format(r, UsageBits(self._iorb_api.get_usage_bits(reg=r)))
                               for r in self._iorb_api.get_regs()]))]
        if self._iorb is not None:
            s_l += ['\tBoth - {{{}}}'.format
                    (','.join(['"{}"-{}'.format(r, UsageBits(self._iorb.get_usage_bits(reg=r)))
                               for r in self._iorb.get_regs()]))]
        return '\n'.join(s_l)


class RegInstruction(sark.code.instruction.Instruction):
    """
    A class used to represent an instruction, using IDA api, analysis of the
        operands, and specially marked instructions to understand the effected
        and used registers.
    """
    def __init__(self, ea=None):
        if ea is None:
            ea = idc.get_screen_ea()

        super(RegInstruction, self).__init__(ea)
        self._operands = [RegOperand(sark_operand=opnd) for opnd in self._operands]

        self._iorb_text = self._analyze_text()
        self._iorb_spec = self._analyze_special()
        self._iorb_api = self._analyze_api()
        self._iorb = self._analyze()

    def _analyze_text(self):
        iorb_text = InsnOpndRegBits()

        for opnd in self.operands:
            iorb_text.mix(opnd.get_iorb_for_source(RegOperand.ANALYZE_STR))

        return iorb_text

    def _analyze_special(self):
        # Add handling for opcodes for which the changed regs and indices were
        #   given explicitly in processor module
        iorb_spec = (conf.proc.op_details_regs(self.mnem,
                                               len(self.operands), self._ea))

        # Add handling for opcodes for which the indices of ld and st were
        #   given explicitly in processor module
        iorb = InsnOpndRegBits()
        ld_arr, st_arr = conf.proc.op_details_idx(self.mnem,
                                                  len(self.operands), self._ea)
        if (ld_arr is not None) and (st_arr is not None):
            for i in (set(ld_arr) | set(st_arr)):
                if i >= len(self.operands):
                    raise ValueError('idx out of operand range', self._ea, i)

                iorb_opnd = self.operands[i].get_iorb_for_source(RegOperand.ANALYZE_BOTH)

                op_bits = 0
                if i in ld_arr:
                    op_bits |= UsageBits.OP_RD
                if i in st_arr:
                    op_bits |= UsageBits.OP_WR

                for reg in iorb_opnd.get_regs():
                    iorb.set_usage_bits(reg, i, op_bits)

                iorb_spec.mix(iorb)

        return iorb_spec

    def _analyze_api(self):
        iorb_api = InsnOpndRegBits()

        for opnd in self.operands:
            iorb_api.mix(opnd.get_iorb_for_source(RegOperand.ANALYZE_API))

        return iorb_api

    # Too costly to analyze a call for all regs. So when asking about a
    #   specific reg, we will analyze it.
    # Depending on processor, we may:
    # 1. Return a specific usage for register (FUNC_CONST)
    # 2. Scan function from start to understand register usage (FUNC_SCAN)
    # 3. Scan function from start to understand register usage, and use some
    #   special function to change it after (FUNC_SCAN with function as
    #   returning param)
    def _analyze_call(self, reg):
        from .reg_frame import rf_func_scan

        if not func_is_call(self._ea):
            return UsageBits.OP_NO

        func_ea = func_get_call_ea(self._ea)

        proc = conf.proc
        handler_type, handler_param = proc.get_call_handle(self._ea, reg)
        if handler_type == proc.FUNC_CONST:
            return handler_param
        elif handler_type == proc.FUNC_SCAN:
            logger.debug('analyzing call {:x} -> {:x} for reg {}'.format(self._ea, func_ea, reg))
            scan_res = rf_func_scan(func_ea, reg)
            if handler_param is not None:
                scan_res = handler_param(func_ea, reg, scan_res)

            logger.debug('finished call {:x} -> {:x} for reg {} - op={}'.format
                         (self._ea, func_ea, reg, UsageBits(scan_res)))
            return scan_res
        else:
            return UsageBits.OP_NO

    # Do the following steps:
    # 1. Analyze the operands textually.
    #   Notice if any returned regs are 'Unknown'
    # 2. Check if we have special handling. If so, finish here.
    # 3. If we did not do special handling (step 1), and there are unknown
    #   regs (step 2), analyze using the IDA API. May require combining data
    #   from textual analyze.
    def _analyze(self):
        iorb = InsnOpndRegBits()

        # 1. Analyze textually
        if self._iorb_text is None:
            self._iorb_text = self._analyze_text()

        iorb.mix(self._iorb_text)

        # 2. Check special handling
        if self._iorb_spec is None:
            self._iorb_spec = self._analyze_special()

        iorb.mix(self._iorb_spec)

        op_bits_list = [iorb.get_usage_bits(reg=r) for r in iorb.get_regs()]
        unk_exists = any(op is UsageBits.OP_UK for op in op_bits_list)

        if (len(self._iorb_spec.get_regs()) != 0) and (not unk_exists):
            return iorb

        # 3. Analyze using API
        if self._iorb_api is None:
            self._iorb_api = self._analyze_api()

        iorb.mix(self._iorb_api)
        return iorb

    @property
    def regs(self):
        return self.get_regs()

    def get_regs(self, op_val=0, op_mask=None):
        return self._iorb.get_masked(op_val=op_val, op_mask=op_mask).get_regs()

    def get_reg_iorb(self, reg):
        call_opbits = self._analyze_call(reg)

        iorb_ret = InsnOpndRegBits()

        if call_opbits != UsageBits.OP_NO:
            iorb_ret.set_usage_bits(reg, UsageBits.NO_OPERAND_IDX, call_opbits)

        if reg in self._iorb.get_regs():
            for opnd_idx in self._iorb.get_opnd_idxs(reg):
                iorb_ret.set_usage_bits(reg, opnd_idx, self._iorb.get_usage_bits(reg, opnd_idx))

        return iorb_ret

    def get_reg_op_bits(self, reg, op_mask=UsageBits.OP_MASK):
        return self.get_reg_iorb(reg).get_usage_bits() & op_mask

    def __repr__(self):
        s_l = []
        s_l += ['<Insn(ea={:x}, mnem={})>'.format(self._ea, self.mnem)]
        if self._iorb_text is not None:
            iorb = self._iorb_text
            s_l += ['\tText:']
            for reg in sorted(iorb.get_regs()):
                reg_op_str_l = ['#{}-{}'.format(op_idx, UsageBits(iorb.get_usage_bits(reg, op_idx)))
                                for op_idx in iorb.get_opnd_idxs(reg)]

                s_l += ['\t\treg "{}" - {{{}}}'.format(reg, ','.join(reg_op_str_l))]

        if (self._iorb_spec is not None) and (len(self._iorb_spec.get_regs()) > 0):
            iorb = self._iorb_spec
            s_l += ['\tSpecial:']
            for reg in sorted(iorb.get_regs()):
                reg_op_str_l = ['#{}-{}'.format(op_idx, UsageBits(iorb.get_usage_bits(reg, op_idx)))
                                for op_idx in iorb.get_opnd_idxs(reg)]

                s_l += ['\t\treg "{}" - {{{}}}'.format(reg, ','.join(reg_op_str_l))]

        if self._iorb_api is not None:
            iorb = self._iorb_api
            s_l += ['\tApi:']
            for reg in sorted(iorb.get_regs()):
                reg_op_str_l = ['#{}-{}'.format(op_idx, UsageBits(iorb.get_usage_bits(reg, op_idx)))
                                for op_idx in iorb.get_opnd_idxs(reg)]

                s_l += ['\t\treg "{}" - {{{}}}'.format(reg, ','.join(reg_op_str_l))]

        if self._iorb is not None:
            iorb = self._iorb
            s_l += ['\tALL:']
            for reg in sorted(iorb.get_regs()):
                reg_op_str_l = ['#{}-{}'.format(op_idx, UsageBits(iorb.get_usage_bits(reg, op_idx)))
                                for op_idx in iorb.get_opnd_idxs(reg)]

                s_l += ['\t\treg "{}" - {{{}}}'.format(reg, ','.join(reg_op_str_l))]

        return '\n'.join(s_l)
