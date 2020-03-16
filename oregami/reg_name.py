import sark

from oregami.reg_utils import logger, is_func, UsageBits
from oregami.reg_insn import RegInstruction
from oregami.reg_utils import AskStr, conf, RegName

# TODOS:
# - if blocks may be consecutive, do only one rename - Done.
# - Add functionality to define as type for all references - Done.
# - If register is used both as load and store (like 'add d5, 5'), may want to
#   somehow mark it as both prev name and new one. Perhaps by putting a
#   comment. Or by renaming to 'new/old'
# - Add check if rename failed
# - If range (after mixing ranges) is across chunks, it will fail
# - If rename fails - tell the user


def rf_rename(rf, regname):
    # TODO: For use and break lines, maybe add in comment. Or rename to
    #   something including both names.

    eas_to_rename = set(insn.ea for insn in rf.get_nobreak_instructions())

    # Get block ranges
    rgs = _get_block_ranges(eas_to_rename, rf.reg)
    rgs = _get_min_block_ranges(rgs, rf.reg)

    # Do renaming
    for s_ea, e_ea in rgs:
        RegName.rename_range(s_ea, e_ea, rf.reg, regname)


def get_name_from_user(ea, reg):
    canon_list = conf.proc.get_reg_list()
    reg_new_name = AskStr(RegName(ea, canon_list).user_name(reg), 'New name for {}'.format(
                          RegName(ea, canon_list).full_name(reg)))
    return reg_new_name


################
# Rename logic #
################

# If between blocks there is no bad usage - make one large range
def _get_min_block_ranges(rgs, reg):
    if len(rgs) == 0:
        return rgs

    logger.debug('Ranges before:')
    for s, e in rgs:
        logger.debug('\t%x:%x' % (s, e))

    rgs_new = []
    rgs_new2 = []
    # assumption - rgs is sorted
    s_first_blk, _ = rgs[0]
    func_start = sark.Function(s_first_blk).start_ea

    # if range between ranges (or between function start and first range)
    #   doesn't contain the reg - add it as range
    curr_s = func_start
    for s_blk, e_blk in rgs:
        dont_extend = False
        for line in sark.lines(curr_s, s_blk):
            # if not code - i.e. a switch-case table, then no reason to
            #   check further
            if not line.is_code:
                continue

            # Trial - if ea not in function, dont_extend
            if ((not is_func(line.ea)) or
                    (sark.Function(line.ea).start_ea != func_start)):
                dont_extend = True
                break

            opbits = RegInstruction(line.ea) \
                .get_reg_op_bits(reg, op_mask=UsageBits.OP_RW |
                                 UsageBits.USAGE_MASK)

            if bool(opbits & UsageBits.USAGE_EXPLICIT) and \
                    bool(opbits & UsageBits.OP_RW):
                # reg was used in line - range cannot include this
                dont_extend = True
                break

        if (not dont_extend) and (curr_s < s_blk):
            rgs_new += [(curr_s, s_blk)]

        rgs_new += [(s_blk, e_blk)]
        curr_s = e_blk

    # if ranges are right after each other - make them one range
    while len(rgs_new) > 0:
        # print rgs_new
        s_blk, e_blk = rgs_new[0]
        rgs_new = rgs_new[1:]

        # while next ranges are consecutive, eat them up
        while len(rgs_new) > 0:
            s_blk2, e_blk2 = rgs_new[0]
            if e_blk != s_blk2:
                break

            e_blk = e_blk2
            rgs_new = rgs_new[1:]

        rgs_new2 += [(s_blk, e_blk)]

    logger.debug('Ranges after:')
    for s, e in rgs_new2:
        logger.debug('\t%x:%x' % (s, e))

    return rgs_new2


def _get_block_ranges(eas, reg):
    ranges = []
    blks = set()
    for ea in eas:
        blk_ea = sark.CodeBlock(ea).start_ea
        blks |= {blk_ea}

    # for blk_ea in blks:
    for blk_ea in sorted(list(blks)):
        # four possible ranges:
        # 1. start till change
        # 2. change till end
        # 3. change till change - in case all references are in one block
        # 4. start till end
        # notice that 1,2 may both happen in a block
        pos1__found_ref = False
        pos1_2__found_change = False
        pos1__first_change_ea = None
        pos2__ref_after_last_change_ea = None
        pos3__first_ref_after_change_ea = None
        pos3__first_change_after_ref_ea = None
        pos4__no_change = True
        blk = sark.CodeBlock(blk_ea)
        for line in blk.lines:
            opbits = RegInstruction(line.ea).get_reg_op_bits(reg, op_mask=UsageBits.OP_RW | UsageBits.USAGE_MASK)

            if line.ea in eas:  # needs to be in range
                if pos1_2__found_change and \
                        (pos2__ref_after_last_change_ea is None):
                    pos2__ref_after_last_change_ea = line.ea

                if pos1_2__found_change and \
                        (pos3__first_change_after_ref_ea is None) and \
                        (pos3__first_ref_after_change_ea is None):
                    pos3__first_ref_after_change_ea = line.ea

                pos1__found_ref = True

            # needs to be not in range
            elif ((line.ea not in eas) and bool(opbits & UsageBits.USAGE_EXPLICIT)
                    and bool(opbits & UsageBits.OP_RW)):
                if (not pos1_2__found_change) and pos1__found_ref:
                    pos1__first_change_ea = line.ea

                if (pos3__first_ref_after_change_ea is not None) and \
                        (pos3__first_change_after_ref_ea is None):
                    pos3__first_change_after_ref_ea = line.ea

                pos2__ref_after_last_change_ea = None
                pos1_2__found_change = True
                pos4__no_change = False

        # possibility 1 - found change after only references
        if pos1__first_change_ea is not None:
            ranges += [(blk.start_ea, pos1__first_change_ea)]
            logger.debug('p1: %x:%x' % (ranges[-1][0], ranges[-1][1]))

        # possibility 2 - found only references after change
        if pos2__ref_after_last_change_ea is not None:
            ranges += [(pos2__ref_after_last_change_ea, blk.end_ea)]
            logger.debug('p2: %x:%x' % (ranges[-1][0], ranges[-1][1]))

        # possibility 3 - found sequrence change->ref->change
        if (pos3__first_ref_after_change_ea is not None) and \
                (pos3__first_change_after_ref_ea is not None):
            ranges += [(pos3__first_ref_after_change_ea,
                        pos3__first_change_after_ref_ea)]
            logger.debug('p3: %x:%x' % (ranges[-1][0], ranges[-1][1]))

        # possibility 4 - no change happened
        if pos4__no_change:
            ranges += [(blk.start_ea, blk.end_ea)]
            logger.debug('p4: %x:%x' % (ranges[-1][0], ranges[-1][1]))

    return ranges
