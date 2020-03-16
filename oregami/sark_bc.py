import sark

##########################################################
# Adding backwards compatability for sark before python3 #
##########################################################
# Sark started using start_ea, end_ea instead of start_ea, end_ea
# We will make the old sark (for python 2.7) support the new names as well
# Notice - we do not support backwards compatability to IDA before 7, which uses different APIs
need_bc = ('start_ea' not in dir(sark.Function))
if need_bc:
    sark.Function.start_ea = property(lambda self: self.startEA)
    sark.Function.end_ea = property(lambda self: self.endEA)
    sark.Line.start_ea = property(lambda self: self.startEA)
    sark.Line.end_ea = property(lambda self: self.endEA)
    sark.code.segment.Segment.start_ea = property(lambda self: self.startEA)
    sark.code.segment.Segment.end_ea = property(lambda self: self.endEA)
    # CodeBlock inherits from idaapi.BasicBlock, and therefore contains both
    # start_ea and startEA (and same for end) - so no need to fix
