import struct
import hashlib
from cachetools import cached, LRUCache

from .reg_insn import *

# TODOS:
# - Maybe if sequence of instructions change reg, handle all as one var.
#   Call it a writers block :P - Done.
# - make this return two dictionaries, with breaks already here - Done.
# - refs in block should return another dictionary of the breaks not in the
#   frame (outbreaks) - Done.
# - Should contain reads that are breaks - Done.
# - make is_load, is_store handle funcs by default - Done.
# - Add some hash of current function flow to the cacheing - so that if the
#   function changes, we will recalculate refs - Done.
# - Add reverse if got to start of func (or no back references) - Done.
# - In _op_details_l, use actual opcode and not the short version. Perhaps add
#   the number of operands as part of the name. - Done
# - add to cache only if took more than X time - No need.
# - make cache work as lru system - Done.
# - Changed usage to not use the should_stop api of processor. Update to
#   include call fucntionality in generic way - Done.
# - sark problem with CodeBlock on non code - add check that in code - Done.
# - if instruction is rw, do both forward and back scan, or do one based on
#   location of cursor - Done.
# - Maybe make another caching specifically for scanning of functions in
#   rf_func_scan - Done
# - if init block only has rw, allow some way of treating it as r only, to see who set it - Done.
# - Add same logic for stack variables (that are sometimes reused)
# - If op changes pc, it is also a call
# - Create flow chart of the usage frame
# - using init stage may allow a flow where r3=0x80000000, and in two
#   branches it is changed to two completely different usages.
# - Maybe add handling for end block, for a register used for return
# - If started not on func, return error.
# - Sometimes there are distinct init blocks. Give a way to know them
# - rf_func_scan can maybe just use BACK scan


class RFOperand(sark.code.instruction.Operand):
    """
    A class used to represent an operand of an instruction in the usage frame of a specific register.
    This class inherits from the sark operand, and as such will be inited the same way.
    The special parameters relevant for its part in the usage frame for a specific register will be set by the
        internal set methods.
    """
    def __init__(self, *l_args, **d_args):
        # If named param for sark_operand exists, copy params internally
        if 'sark_operand' in d_args:
            self.__dict__.update(d_args['sark_operand'].__dict__)
        else:
            super(RFOperand, self).__init__(*l_args, **d_args)

        self._uf_line = None
        if 'uf_line' in d_args:
            self._uf_line = d_args['uf_line']

        self.uf_reg = None
        self._uf_opnd_bits = 0

        self.uf_is_read = False
        self.uf_is_write = False
        self.uf_is_implicit = False

    def set_reg_opnds_bits(self, reg, opnd_bits):
        """
        Set the usage frame relevant parameters

        Attributes
        ----------
        reg : str
            The canonical name of the register
        opnd_bits : int
            the operand bitfield, denoting the usage of the register in
                the operand
        """
        self.uf_reg = reg
        self._uf_opnd_bits = opnd_bits

        self.uf_is_read = bool(opnd_bits & UsageBits.OP_RD)
        self.uf_is_write = bool(opnd_bits & UsageBits.OP_WR)

        # Should never be a situation where there is an operation which is both not explicit, and not implicit
        if (opnd_bits != 0
                and (not bool(opnd_bits & UsageBits.USAGE_EXPLICIT))
                and (not bool(opnd_bits & UsageBits.USAGE_IMPLICIT_MASK))):
            logger.error('{:x} <operand {}, reg {}> - opnd_bits={}'.format(
                         self._ea, self.n, self.uf_reg, UsageBits(opnd_bits)))

        self.uf_is_implicit = bool(opnd_bits & UsageBits.USAGE_IMPLICIT_MASK)

    @property
    def uf_is_external(self):
        # If no usage - then external
        if self.op_type & UsageBits.OP_RW == UsageBits.OP_NO:
            return True

        # If is used - depends on line type
        if self._uf_line is not None:
            ul = self._uf_line

            if ul.is_break:
                if self.op_type & UsageBits.OP_RW == UsageBits.OP_WR:
                    return True
                else:
                    return False

            elif ul.is_outbreak:
                return True

            elif ul.is_init or ul.is_pure:
                return False

        return False

    @property
    def ref_type(self):
        return self._uf_opnd_bits & UsageBits.USAGE_MASK

    @property
    def op_type(self):
        return self._uf_opnd_bits & UsageBits.OP_MASK

    @property
    def op_flags(self):
        return self._uf_opnd_bits

    def __str__(self):
        s = ''
        if self.uf_is_read:
            s += 'r'
        if self.uf_is_write:
            s += 'w'
        if self.uf_is_implicit:
            s += 'i'
        if self.uf_is_external:
            s += 'x'

        return '<UF-Operand {:x}, {}, {}-{}>'.format(self._ea, self.n, self.uf_reg, s)


class RFInstruction(sark.code.instruction.Instruction):
    """
    A class used to represent an instruction in the usage frame of a specific register.
    """
    TYPE_EMPTY = 0
    TYPE_INIT = 1
    TYPE_BREAK = 2
    TYPE_PURE = 4
    TYPE_OUTBREAK = 8

    TYPE_IN_MASK = TYPE_INIT | TYPE_BREAK | TYPE_PURE
    TYPE_MASK = TYPE_IN_MASK | TYPE_OUTBREAK

    EXPLICIT_BRK = 16

    def __init__(self, ea, reg, iorb):
        """
        Attributes
        ----------
        ea : address
            The address of the current instruction
        reg : str
            The canonical name of the register
        iorb : InsnOpndRegBits
            The information about the usage bits per operand for the register
        """
        super(RFInstruction, self).__init__(ea)
        self.reg = reg

        self._operands = [RFOperand(sark_operand=opnd, uf_line=self) for opnd in self._operands]

        for ufop in self._operands:
            opnds_bits = 0 if ufop.n not in iorb.get_opnd_idxs(reg) else iorb.get_usage_bits(reg, ufop.n)
            ufop.set_reg_opnds_bits(reg, opnds_bits)

        # Handle non operand bits - such as call
        non_opnd_bits = 0 if UsageBits.NO_OPERAND_IDX not in iorb.get_opnd_idxs(reg) \
            else iorb.get_usage_bits(reg, UsageBits.NO_OPERAND_IDX)

        self._type = 0

        self._op_flags = reduce(lambda x, y: x | y,
                                [operand.op_flags
                                 for operand in self._operands], non_opnd_bits)

    @property
    def ea(self):
        return self._ea

    @property
    def op_flags(self):
        return self._op_flags

    def set_type(self, op_type):
        self._type |= op_type

    def unset_type(self, op_type):
        self._type &= ~op_type

    @property
    def type(self):
        return self._type

    @property
    def is_init(self):
        return bool(self.type & RFInstruction.TYPE_INIT)

    @property
    def is_break(self):
        return bool(self.type & RFInstruction.TYPE_BREAK)

    @property
    def is_pure(self):
        return bool(self.type & RFInstruction.TYPE_PURE)

    @property
    def is_outbreak(self):
        return bool(self.type & RFInstruction.TYPE_OUTBREAK)

    @property
    def is_explicit_brk(self):
        return not bool(self._op_flags & RFInstruction.EXPLICIT_BRK)

    @property
    def is_read(self):
        return bool(self._op_flags & UsageBits.OP_RD)

    @property
    def is_write(self):
        return bool(self._op_flags & UsageBits.OP_WR)

    @property
    def is_implicit(self):
        return not bool(self._op_flags & UsageBits.USAGE_EXPLICIT)

    def __str__(self):
        s = ''
        if self.is_read:
            s += 'r'
        if self.is_write:
            s += 'w'
        if self.is_implicit:
            s += 'i'

        types = []
        if self.is_init:
            types += ['init']
        if self.is_break:
            types += ['break']
        if self.is_pure:
            types += ['pure']
        if self.is_outbreak:
            types += ['outbreak']

        return '<UF-Instruction {:x}, {{{}}}, {}-{}>'.format(self._ea, '|'.join(types), self.reg, s)


class RegFrame(object):
    """
    A class used to represent a usage frame of a specific register.
    """
    DIR_BACK = 0
    DIR_FORWARD = 1
    DIR_BOTH = 2

    #################
    # Caching logic #
    #################

    # These functions are a hack, intended to utilize the caching of the analyzed usage frame.
    # The assumption is that the same RegFrame should be created for all addresses in the usage frame
    # (not including breaks - which would be part of another usage frame if we initiated a scan starting from them)

    _cached_rf = None

    def __new__(cls, ea, reg, **kargs):
        init_stage_bool = kargs.get('init_stage_bool', True)
        force = kargs.get('force', False)
        direction = kargs.get('direction', RegFrame.DIR_BOTH)
        quiet = kargs.get('quiet', False)

        orig_log_lvl = conf.logger.getEffectiveLevel()
        if quiet:
            conf.logger.setLevel(logging.CRITICAL)

        orig_ea = ea
        f_hash = RegFrame._get_func_hash(orig_ea)

        if force:
            rf = RegFrame._get_and_cache(cls, orig_ea, reg, init_stage_bool, direction, f_hash)
        elif direction == RegFrame.DIR_BOTH:
            rf = RegFrame._cached_new(cls, orig_ea, reg, init_stage_bool, f_hash)
        else:
            rf = RegFrame._cached_new_dir(cls, orig_ea, reg, init_stage_bool, direction, f_hash)

        if quiet:
            conf.logger.setLevel(orig_log_lvl)

        return rf

    @staticmethod
    @cached(cache=LRUCache(maxsize=1000))
    def _cached_new(cls, orig_ea, reg, init_stage_bool, f_hash):
        if RegFrame._cached_rf is not None:
            return RegFrame._cached_rf

        return RegFrame._get_and_cache(cls, orig_ea, reg, init_stage_bool, RegFrame.DIR_BOTH, f_hash)

    @staticmethod
    @cached(cache=LRUCache(maxsize=1000))
    def _cached_new_dir(cls, orig_ea, reg, init_stage_bool, direction, f_hash):
        if RegFrame._cached_rf is not None:
            return RegFrame._cached_rf

        return RegFrame._get_and_cache(cls, orig_ea, reg, init_stage_bool, direction, f_hash)

    @staticmethod
    def _get_and_cache(cls, orig_ea, reg, init_stage_bool, direction, f_hash):
        rf = super(RegFrame, cls).__new__(cls)
        super(RegFrame, rf).__init__()
        # __init__ will be called by default after __new__ was returned.
        # To prevent a double call to __init__ logic, we will use _skip_init.
        # After the first call, it will be marked to skip the next call
        rf._skip_init = False
        rf.__init__(orig_ea, reg, init_stage_bool=init_stage_bool, direction=direction, force=False)
        rf._skip_init = True

        nb_ea_set = set(insn.ea for insn in rf.get_nobreak_instructions())
        br_ea_set = set(insn.ea for insn in rf.get_break_instructions())
        exp_ea_set = set(insn.ea for insn in rf.get_explicit_break_instructions())
        
        # If we scan an instruction that does not contain the register, don't cache all found instructions.
        # (because it may cause mistakes - the flow logic assumes that we only reverse in a block containing
        # a usage, and this will do both directions on first block even if there is no usage there)
        if (orig_ea not in (nb_ea_set | br_ea_set)) or (orig_ea in exp_ea_set):
            return rf

        # make sure all eas are entered in cache, by calling __new__ on them
        RegFrame._cached_rf = rf
        
        for ea in nb_ea_set:
            RegFrame._cached_new(cls, ea, reg, init_stage_bool, f_hash)
        for ea in br_ea_set:
            RegFrame._cached_new_dir(cls, ea, reg, init_stage_bool, RegFrame.DIR_BACK, f_hash)
            
        RegFrame._cached_rf = None

        return rf

    @staticmethod
    def _get_func_hash(ea):
        m = hashlib.md5()
        ea = sark.Function(ea).start_ea
        blk = sark.CodeBlock(ea)
        scanned_blks = set()
        rem_blks = [blk]
        scanned_blks.add(blk.start_ea)

        while len(rem_blks):
            blk = rem_blks[0]
            rem_blks = rem_blks[1:]
            m.update(b's')
            m.update(struct.pack(">Q", blk.start_ea))

            for n_blk in blk.next:
                m.update(struct.pack(">Q", n_blk.start_ea))
                if n_blk.start_ea not in scanned_blks:
                    rem_blks += [n_blk]
                    scanned_blks.add(n_blk.start_ea)

        return m.digest()

    def __init__(self, ea, reg, ** kargs):
        """
        Attributes
        ----------
        ea : address
            An address from which the scan should begin. If an instruction contains both a read and write of a
            register (eg. 'r3 = r3 + r4'), the scan will necessarily go forward (to instructions using the
            register). It will possibly go backwards - depending on the init_stage_bool attribute.

        reg : str
            The canonical name of the register

        init_stage_bool : bool (default - True)
            A boolean deciding whether we are assuming an init stage of the register, or if we assume that
            the usage frame should only include the last write into the register.

        direction : int (default - DIR_BOTH)
            An enum, determining the direction of the scan. This will only have an effect in two cases:
            1. The input address an RW instruction. By default it is assumed that this instruction
                is part of the init, and will therefore go forward. Using this enum, we may make 
                the scan go backwards and assume that the instruction is a break.
            2. The input address is an explicit break such as a function call. By default, the scan
                will go both forward and backwards, even if the function uses and/or changes the register.
                In order to see only the register inputted into the function (ie. before the explicit break)
                or after the function (ie. after the explicit break), this enum can be used.

        force : bool (default - False)
            A boolean deciding if we should force a rescan. This class supports caching the scan results be
            default, so that asking for the RegFrame on any instruction that is part of this usage frame
            will return the previously analyzed RegFrame. You may choose to force a rescan even for a cached
            usage frame by using this parameter.

        quiet: bool (default - False)
            A boolean deciding if we should be quiet - ie. make the logger not send any prints out.
            This is usefull mainly for other scripts using this class, which don't want the output to
            contain too much noise.

        Examples
        --------
        (*) - denotes instructions that were found to be part of the usage frame
        1. reg=r3, ea=1003, init_stage_bool=True
            assembly:
                1000: r3 = 2
                1001: r4 = 5
                1002: r3 = 0x10000 (*)
                1003: r3 += 0x48 (*)
                1004: r4 = r3[4] (*)
                1005: r3 = r3 + 8 (*)
                1006: r5 = r3[0]

            In this example, we include both lines 1002, 1003 as part of the usage frame, because they
            are both part of the 'init stage', the stage that sets a new value into the register (and may be
            composed of more that one opcode, especially when building a number larger than 0xffff)

        2. reg=r3, ea=1003, init_stage_bool=False
            assembly:
                1000: r3 = 2
                1001: r4 = 5
                1002: r3 = 0x10000
                1003: r3 += 0x48 (*)
                1004: r4 = r3[4] (*)
                1005: r3 = r3 + 8 (*)
                1006: r5 = r3[0]

            In this example, we assume that there is no 'init stage'.
            Therefore, the scan will not include line 1002 - because line 1003 already changed r3, so the
            usage frame should not include opcodes before it.

        """

        # Part of the caching hack
        if self._skip_init:
            return

        self.reg = reg
        self.init_stage_bool = kargs.get('init_stage_bool', True)
        direction = kargs.get('direction', True)
        self._analyze(ea, direction)

    def get_instruction(self, ea):
        """
        Returns the RegInstruction for the address ea in this usage frame.
        If not part of the usage frame (or one of the "outbreaks" - instructions that caused us to break
        the scan and should not be included in the usage frame), will return None.
        """
        if ea in self.uf_instructions:
            return self.uf_instructions[ea]
        else:
            return None

    # generator for going over instructions in usage frame
    def _get_instructions(self, flags, notflags=0):
        for ea in sorted(self.uf_instructions.keys()):
            if bool(self.uf_instructions[ea].type & flags) and (not bool(self.uf_instructions[ea].type & notflags)):
                yield self.uf_instructions[ea]

    def get_instructions(self, with_outbreaks=False):
        """
        Returns a generator of RegInstructions for all instructions included in the usage frame.
        By using with_outbreaks=True, this may also include instructions that caused the scanning to break,
        such as instructions writing a new value into the register.
        """
        flags = RFInstruction.TYPE_INIT | RFInstruction.TYPE_PURE | RFInstruction.TYPE_BREAK
        if with_outbreaks:
            flags |= RFInstruction.TYPE_OUTBREAK

        return self._get_instructions(flags)

    def get_init_instructions(self):
        """
        Returns a generator of RegInstructions for instructions that are a part of the 'init stage' of
        the register.
        """
        return self._get_instructions(RFInstruction.TYPE_INIT)

    def get_pure_instructions(self):
        """
        Returns a generator of RegInstructions for instructions that 'purely' used the register - meaning that
        it used the register data without changing it in any way.
        """
        return self._get_instructions(RFInstruction.TYPE_PURE)

    def get_nobreak_instructions(self):
        """
        Returns a generator of RegInstructions for instructions that are part of the usage frame - but did
        not cause us to break our scan.
        """
        return self._get_instructions(RFInstruction.TYPE_PURE | RFInstruction.TYPE_INIT)

    def get_noinit_instructions(self):
        """
        Returns a generator of RegInstructions for instructions that are part of the usage frame - but are
        not part of the 'init stage'.
        """
        return self._get_instructions(RFInstruction.TYPE_PURE | RFInstruction.TYPE_BREAK)

    def get_break_instructions(self):
        """
        Returns a generator of RegInstructions for instructions that used the register value, but then
        changed its value - and so caused us to 'break' the scan.
        """
        return self._get_instructions(RFInstruction.TYPE_BREAK)

    def get_outbreak_instructions(self):
        """
        Returns a generator of RegInstructions for instructions that caused us to 'break' the scan, but
        should not be included in the usage frame.
        For example, an opcode setting a new value into the register.
        """
        return self._get_instructions(RFInstruction.TYPE_OUTBREAK)

    def get_explicit_break_instructions(self):
        """
        Returns a generator of RegInstructions for instructions that explicitly tried to 'break' the scan.
        For example, a call to function that used or changed the register.
        """
        return self._get_instructions(RFInstruction.EXPLICIT_BRK)

    ####################
    # Scanning Methods #
    ####################

    def _analyze(self, ea, direction):
        reg = self.reg
        orig_direction = direction

        logger.info('Start scan - ea={:x}, reg={}, init_stage_bool={}'.format(ea, reg, self.init_stage_bool))
        ea = sark.Line(ea).ea  # get ea that is start of line

        blk = sark.CodeBlock(ea)

        used_blks = set()

        fw_init_state = False
        bk_init_state = False
        fw_stop_state = False
        bk_stop_state = False
        self.uf_instructions = {}

        # check curr
        rinstruction = RegInstruction(ea)

        op_bits = rinstruction.get_reg_op_bits(reg)
        logger.debug('Start is {}'.format(UsageBits(op_bits)))

        uf_l = None
        if ea in self.uf_instructions:
            uf_l = self.uf_instructions[ea]        
        elif bool(op_bits & (UsageBits.OP_RW | UsageBits.OP_BRK)):
            uf_l = RFInstruction(ea, reg, rinstruction.get_reg_iorb(reg))

        # Only handle the stop and init states for first instruction.
        # Its type will be determined after the entire scan (to differentiate between RW that is init,
        # and RW that is break)
        
        if op_bits & UsageBits.OP_RW == UsageBits.OP_WR:
            # If we don't want to support init stage, we will not mark this as init_state, so
            # that any RW encountered forward will be regarded as break
            if self.init_stage_bool:
                fw_init_state = True            
            bk_stop_state = True

        elif op_bits & UsageBits.OP_RW == UsageBits.OP_RW:
            # If the direction is back, we will go back without any assumptions on this instruction
            # (ie. no init state, no break state)
            if direction != RegFrame.DIR_BACK:
                # If we don't want to support init stage, we will not mark this as init_state, so
                # that any RW encountered forward will be regarded as break
                # Moreover, we will want to go only forward, because this instruction is the only
                # init instruction we expect.
                if self.init_stage_bool:
                    fw_init_state = True
                    bk_init_state = True
                else:
                    bk_stop_state = True
            # when going back from rw, unless there are only inits before, we would like to break.
            else:
                # if we are not the first in our block, just do regular scan starting from previous instruction
                if sark.CodeBlock(ea).start_ea != ea:
                    new_ea = sark.Line(ea).prev.ea
                    logger.debug('Restarting scan for {:x}, dir={}'.format(new_ea, EnumClass(self)[RegFrame.DIR_BOTH]))
                    return self._analyze(new_ea, self.DIR_BOTH)
                # else, just go backwards. Not done when not first, because it is a problem to reverse mid
                # block if some other usage was found in block
                else:
                    fw_stop_state = True

        # Handle case of implicit break.
        if op_bits & UsageBits.OP_BRK == UsageBits.OP_BRK:
            uf_l.set_type(RFInstruction.EXPLICIT_BRK)
            if direction == RegFrame.DIR_BACK:
                fw_stop_state = True
            elif direction == RegFrame.DIR_FORWARD:
                bk_stop_state = True            
            else:
                # In case of explicit break, we want to go both back and forward (for instance, checking
                # a register which is both input and output on a function call. We want to see both before
                # and after the function.
                pass

        if uf_l is not None:
            self.uf_instructions[ea] = uf_l

        handling_queue = []
        # Add forward handling
        if not fw_stop_state:
            handling_queue += [(ea, blk.end_ea, RegFrame.DIR_FORWARD,
                                fw_init_state, True)]
        # Add backward handling - if not stopped
        if not bk_stop_state:
            handling_queue += [(blk.start_ea, ea, RegFrame.DIR_BACK,
                                bk_init_state, True)]

        # go over handling queue blks - until there are no more handling queue tuple:
        #   (start_ea, end_ea, direction, init_state, first_blk_bool)
        while len(handling_queue) > 0:
            s_ea, e_ea, direction, init_state, first_blk_bool = handling_queue[0]
            handling_queue = handling_queue[1:]

            blk = sark.CodeBlock(s_ea)

            # When going forward in first block, we already handled first op.
            # Skip it.
            if first_blk_bool and (direction == RegFrame.DIR_FORWARD):
                # next ea
                s_ea = sark.Line(s_ea).end_ea

            logger.debug('parsing: {:x} : {:x} , {}, init_state={}'.format(s_ea, e_ea, EnumClass(self)[direction],
                                                                           ['False', 'True'][init_state]))

            blk_found_usage, blk_stop_state, blk_init_state, rev_init_state = \
                self._get_refs_blk(s_ea, e_ea, direction, init_state, reg)

            should_rev = False

            # When scanning the first block, the reverse is already being handled
            if not first_blk_bool:
                if blk_found_usage:
                    should_rev = True
                    logger.debug('found instructions in blk. reversing')

                # Adding case for usage of register which is a function parameter.
                # In this case, we will be going backwards in the entrance block of the function, without a
                #   reason to stop. We also don't expect an init_stage in this case, because the incoming parameter
                #   has a minimum usage frame itself, before changing. (ie. if the input param r3, is later
                #   changed with 'r3=r3+0x10', this is a different variable then the input param)
                # if we are going backwards in entrance block of function, and there was no usage or reason
                #   to stop - this is the case of a register which is actually a function parameter
                elif ((direction == RegFrame.DIR_BACK) and
                      (blk.start_ea == sark.Function(blk.start_ea).start_ea) and
                      (not blk_stop_state) and (not blk_init_state)):
                    should_rev = True
                    logger.debug('entrance block. reversing')

            # if we found loads -> add reverse direction for block, and use same rev_init_state returned
            # by the block scan.
            if should_rev:
                blks = list()
                if direction == RegFrame.DIR_FORWARD:
                    blks = blk.prev
                else:  # direction == RegFrame.DIR_BACK:
                    blks = blk.next

                for e_blk in blks:
                    # Sometimes, sark will return an empty block, outside the func. If so, skip it.
                    if e_blk.start_ea == e_blk.end_ea:
                        continue

                    if (1-direction, e_blk.start_ea) not in used_blks:
                        logger.debug('added (rev) - {:x} : {:x} , {}'.
                                     format(e_blk.start_ea, e_blk.end_ea, EnumClass(self)[1-direction]))
                        used_blks.add((1-direction, e_blk.start_ea))
                        handling_queue += [(e_blk.start_ea, e_blk.end_ea, 1-direction, rev_init_state, False)]

            # if didn't stop -> add blocks in same direction, and use new init_state
            if not blk_stop_state:
                if direction == RegFrame.DIR_FORWARD:
                    blks = blk.next
                elif direction == RegFrame.DIR_BACK:
                    blks = blk.prev

                for e_blk in blks:
                    # Sometimes, sark will return an empty block, outside the func. If so, skip it.
                    if e_blk.start_ea == e_blk.end_ea:
                        continue

                    if (direction, e_blk.start_ea) not in used_blks:
                        logger.debug('added (same) - {:x} : {:x}, {}'.format(e_blk.start_ea, e_blk.end_ea,
                                                                             EnumClass(self)[direction]))
                        used_blks.add((direction, e_blk.start_ea))
                        handling_queue += [(e_blk.start_ea, e_blk.end_ea, direction, blk_init_state, False)]

        # Go back to the original ea. If it was used, but its type was not set yet, do it now
        if (ea in self.uf_instructions) and \
                ((self.uf_instructions[ea].type & RFInstruction.TYPE_IN_MASK) == RFInstruction.TYPE_EMPTY):

            ufl = self.uf_instructions[ea]
            is_explicit_brk = bool(self.uf_instructions[ea].type & RFInstruction.EXPLICIT_BRK)
            
            if op_bits & UsageBits.OP_RW == UsageBits.OP_WR:
                uf_l.set_type(RFInstruction.TYPE_INIT)
                logger.debug('(FIRST) ADD INIT: {:x}'.format(ea))
            elif op_bits & UsageBits.OP_RW == UsageBits.OP_RD:
                uf_l.set_type(RFInstruction.TYPE_PURE)
                logger.debug('(FIRST) ADD PURE: {:x}'.format(ea))
            elif op_bits & UsageBits.OP_RW == UsageBits.OP_RW:
                if orig_direction == RegFrame.DIR_BACK:
                    # If the direction was BACK, but the instruction doesn't have a type yet, it means
                    # that no other relevant usage was encountered. Which means we must scan again,
                    # but this time including forward. 
                    # Unless it was an explicit break - in this case just end it.
                    if not is_explicit_brk:
                        logger.debug('In back scan, no type found. Restarting scan for {:x}, dir={}'.
                                     format(ea, EnumClass(self)[RegFrame.DIR_BOTH]))
                        return self._analyze(ea, RegFrame.DIR_BOTH)
                    else:
                        uf_l.set_type(RFInstruction.TYPE_BREAK)
                        logger.debug('(FIRST) ADD BREAK: {:x}'.format(ea))
                        
                elif orig_direction == RegFrame.DIR_FORWARD:
                    # If the direction was FORWARD, but the instruction doesn't have a type yet, it means
                    # that no other relevant usage was encountered. Which means we must scan again,
                    # but this time including backwards. 
                    # Unless it was an explicit break - in this case just end it.                
                    if not is_explicit_brk:
                        logger.debug('In forward scan, no type found. Restarting scan for {:x}, dir={}'.
                                     format(ea, EnumClass(self)[RegFrame.DIR_BOTH]))
                        return self._analyze(ea, RegFrame.DIR_BOTH)

                    uf_l.set_type(RFInstruction.TYPE_INIT)
                    logger.debug('(FIRST) ADD INIT: {:x}'.format(ea))
                    
                else:  # BOTH
                    uf_l.set_type(RFInstruction.TYPE_INIT)
                    logger.debug('(FIRST) ADD INIT: {:x}'.format(ea))

            self.uf_instructions[ea] = ufl

        for insn in self.uf_instructions.values():
            # Sometimes a break from one direction, is an init stage from another direction.
            # Update out breaks so they wont contain found instructions
            # Sometimes a break from one direction, is a 'use and break' from another direction.
            # Update out breaks so they wont contain found instructions
            if (bool(insn.type & RFInstruction.TYPE_OUTBREAK) and
                    (bool(insn.type & RFInstruction.TYPE_IN_MASK))):
                logger.debug('Found both outbreak and others in {:x}'.format(insn.ea))
                insn.unset_type(RFInstruction.TYPE_OUTBREAK)

        # Finished analyzing. This is the conclusion of the results.
        for ea in sorted(self.uf_instructions.keys()):
            if bool(self.uf_instructions[ea].type & RFInstruction.TYPE_INIT):
                logger.debug('Init instruction: <{:x}> [{}]'
                             .format(ea, UsageBits(self.uf_instructions[ea].op_flags)))

        for ea in sorted(self.uf_instructions.keys()):
            if bool(self.uf_instructions[ea].type & RFInstruction.TYPE_PURE):
                logger.debug('Pure use instruction: <{:x}> [{}]'
                             .format(ea, UsageBits(self.uf_instructions[ea].op_flags)))

        for ea in sorted(self.uf_instructions.keys()):
            if bool(self.uf_instructions[ea].type & RFInstruction.TYPE_BREAK):
                logger.debug('Use and break instruction: <{:x}> [{}]'
                             .format(ea, UsageBits(self.uf_instructions[ea].op_flags)))

        for ea in sorted(self.uf_instructions.keys()):
            if bool(self.uf_instructions[ea].type & RFInstruction.TYPE_OUTBREAK):
                logger.debug('Out-break instruction: <{:x}> [{}]'
                             .format(ea, UsageBits(self.uf_instructions[ea].op_flags)))

    def _get_refs_blk(self, s_ea, e_ea, direction, init_state, reg):
        if direction == RegFrame.DIR_FORWARD:
            return self._get_refs_blk_fw(s_ea, e_ea, init_state, reg)
        elif direction == RegFrame.DIR_BACK:
            return self._get_refs_blk_bk(s_ea, e_ea, init_state, reg)

    def _get_refs_blk_fw(self, s_ea, e_ea, init_state, reg):
        lines = sark.lines(start=s_ea, end=e_ea)

        rev_init_state = init_state
        stop_state = False
        found_usage = False
        found_init = False
        for line in lines:
            if stop_state:
                break

            uinsn = None
            rinsn = RegInstruction(line.ea)
            op_bits = rinsn.get_reg_op_bits(reg)

            if line.ea in self.uf_instructions.keys():
                uinsn = self.uf_instructions[line.ea]
            elif bool(op_bits & (UsageBits.OP_RW | UsageBits.OP_BRK)):
                uinsn = RFInstruction(line.ea, reg, rinsn.get_reg_iorb(reg))

            if op_bits & UsageBits.OP_RW == UsageBits.OP_RD:
                init_state = False
                uinsn.set_type(RFInstruction.TYPE_PURE)
                found_usage = True
                logger.debug('ADD PURE: {:x}'.format(line.ea))
            elif op_bits & UsageBits.OP_RW == UsageBits.OP_WR:
                uinsn.set_type(RFInstruction.TYPE_OUTBREAK)
                logger.debug('ADD OUTBREAK: {:x}'.format(line.ea))
                stop_state = True
            elif op_bits & UsageBits.OP_RW == UsageBits.OP_RW:
                if init_state:
                    uinsn.set_type(RFInstruction.TYPE_INIT)
                    logger.debug('ADD INIT: {:x}'.format(line.ea))
                    found_usage = True
                    found_init = True
                else:
                    uinsn.set_type(RFInstruction.TYPE_BREAK)
                    logger.debug('ADD BREAK: {:x}'.format(line.ea))
                    found_usage = True
                    stop_state = True

            if op_bits & UsageBits.OP_BRK == UsageBits.OP_BRK:
                uinsn.set_type(RFInstruction.EXPLICIT_BRK)
                stop_state = True

            if uinsn is not None:
                self.uf_instructions[line.ea] = uinsn

        # If this block had only RD (no init), than when scanning backwards we don't want to require init state
        if not found_init:
            rev_init_state = False

        return found_usage, stop_state, init_state, rev_init_state

    def _get_refs_blk_bk(self, s_ea, e_ea, init_state, reg):
        lines = sark.lines(start=s_ea, end=e_ea, reverse=True)

        rev_init_state = init_state

        stop_state = False
        found_usage = False
        for line in lines:
            if stop_state:
                break

            uinsn = None
            rinsn = RegInstruction(line.ea)
            op_bits = rinsn.get_reg_op_bits(reg)

            if line.ea in self.uf_instructions.keys():
                uinsn = self.uf_instructions[line.ea]
            elif bool(op_bits & (UsageBits.OP_RW | UsageBits.OP_BRK)):
                uinsn = RFInstruction(line.ea, reg, rinsn.get_reg_iorb(reg))

            if op_bits & UsageBits.OP_RW == UsageBits.OP_RD:
                if init_state:
                    logger.debug('ADD OUTBREAK: {:x}'.format(line.ea))
                    uinsn.set_type(RFInstruction.TYPE_OUTBREAK)
                    stop_state = True
                else:
                    logger.debug('ADD PURE: {:x}'.format(line.ea))
                    uinsn.set_type(RFInstruction.TYPE_PURE)
                    found_usage = True
            elif op_bits & UsageBits.OP_RW == UsageBits.OP_WR:
                logger.debug('ADD INIT (and stop): {:x}'.format(line.ea))
                uinsn.set_type(RFInstruction.TYPE_INIT)
                found_usage = True
                init_state = False
                stop_state = True
            elif op_bits & UsageBits.OP_RW == UsageBits.OP_RW:
                logger.debug('ADD INIT: {:x}'.format(line.ea))
                uinsn.set_type(RFInstruction.TYPE_INIT)
                found_usage = True
                init_state = True

            if op_bits & UsageBits.OP_BRK == UsageBits.OP_BRK:
                uinsn.set_type(RFInstruction.EXPLICIT_BRK)
                stop_state = True

            # If we don't want to support init_stage, we will stop after encountering either
            # UsageBits.OP_RW or UsageBits.OP_WR.
            if (self.init_stage_bool is False) and init_state:
                stop_state = True
                init_state = False

            if uinsn is not None:
                self.uf_instructions[line.ea] = uinsn

        return found_usage, stop_state, init_state, rev_init_state


# make sure we don't enter a loop of function when diving into a funcA calling
#   funcB calling funcA etc.
_funcs_in_call_dive = []


@cached(cache=LRUCache(maxsize=1000))
def rf_func_scan(ea, reg):
    global _funcs_in_call_dive
    if ea in _funcs_in_call_dive:
        return UsageBits.OP_NO

    _funcs_in_call_dive.append(ea)
    logger.debug('Current call stack: ' + '->'.join(['{:x}'.format(x) for x in _funcs_in_call_dive]))

    rf = RegFrame(ea, reg, init_stage_bool=False)

    _funcs_in_call_dive.remove(ea)

    opbits = UsageBits.OP_NO

    # We would like to simulate the case of starting the scan 'before' the function.
    # Because we can only start at the first instruction, we need to handle the case of a 'w' in this
    # instruction in a different way (because it is a 'break' if we were to actually start before).
    # If the start of function is already a 'w' operation, then it will only be 'r' if it happens in
    # the same instruction.
    insn_start = rf.get_instruction(ea)
    if (insn_start is not None) and insn_start.is_init:
        opbits = insn_start.op_flags | UsageBits.USAGE_IMPLICIT_FUNC_CHANGED
        return opbits

    pure_instructions = [insn for insn in rf.get_pure_instructions()]
    break_instructions = [insn for insn in rf.get_break_instructions()]
    outbreak_instructions = [insn for insn in rf.get_outbreak_instructions()]

    if len(pure_instructions)+len(break_instructions) > 0:
        opbits |= UsageBits.OP_RD
    if len(break_instructions)+len(outbreak_instructions) > 0:
        opbits |= UsageBits.OP_WR
    if opbits != UsageBits.OP_NO:
        opbits |= UsageBits.USAGE_IMPLICIT_FUNC_CHANGED

    logger.debug('pure instructions: {}'.format(repr(pure_instructions)))
    return opbits
