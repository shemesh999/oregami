from oregami.reg_frame import *
from oregami.reg_utils import *


class Oregami(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "oREGami"
    help = "Find references to register in function"
    wanted_name = "OregamiWindow"
    wanted_hotkey = "Shift+X"

    @staticmethod
    def init():
        return idaapi.PLUGIN_OK

    @staticmethod
    def term():
        pass

    @staticmethod
    def run(arg):
        start, _ = sark.get_selection()

        oregami_plugin_starter(start)


def PLUGIN_ENTRY():
    return Oregami()


def oregami_plugin_starter(orig_ea):
    reg = get_reg_from_user(orig_ea)

    if reg is None:
        return

    rf = RegFrame(orig_ea, reg, force=(not conf.cache_bool))

    rx = RegXref(reg=reg, ea=orig_ea)
    eas = []

    for insn in rf.get_instructions():
        rx.add_xref(insn.ea, insn.is_read, insn.is_write, insn.is_implicit)
        eas += [insn.ea]

    if orig_ea in eas:
        idx = eas.index(orig_ea)
        rx.deflt = idx

    item_idx = rx.Show(True)
    if item_idx >= 0:
        ida_kernwin.jumpto(eas[item_idx])


class RegXref(idaapi.Choose):
    def __init__(self, reg, ea=None, icon=55, flags=0, width=None,
                 height=None, embedded=False, modal=False):
        title = 'xrefs to {}'.format(reg)
        idaapi.Choose.__init__(
            self,
            title,
            [["Direction", 5], ["Type", 7], ["Address", 7], ["Text", 40]],
            width=width,
            height=height,
            embedded=embedded,
            flags=flags)
        self.n = 0
        self.items = []
        self.icon = icon
        self.selcount = 0
        self.modal = modal
        self.popup_names = []
        self.ea = ea
        self.title = title
        # 80 - str
        # 52 - type
        # 54 - reg?

    def add_xref(self, ea, is_read, is_write, is_implicit):
        if ea < self.ea:
            direction = '^'
        elif ea > self.ea:
            direction = 'v'
        else:
            direction = '.'

        addr = '0x%x' % ea

        type_str = ''
        if is_read:
            type_str += 'r'
        if is_write:
            type_str += 'w'
        if (not is_read) and (not is_write):
            type_str += '{unknown}'

        if is_implicit:
            type_str += ' {implicit}'

        text = sark.Line(ea).disasm
        self.items.append([direction, type_str, addr, text])

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show(self.modal) >= 0

    @staticmethod
    def make_item(reg):
        return [reg, reg]

    # In old IDA does require other funcs be implemented
    def OnClose(self):
        return
