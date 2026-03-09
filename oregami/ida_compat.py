import idaapi
import ida_typeinf
import ida_kernwin

IDA9 = idaapi.IDA_SDK_VERSION >= 900

if not IDA9:
    import ida_struct


def compat_get_struc_id(type_name):
    if IDA9:
        return ida_typeinf.get_named_type_tid(type_name)
    return ida_struct.get_struc_id(type_name)


def compat_get_struc_name(tid):
    if IDA9:
        return ida_typeinf.get_tid_name(tid)
    return ida_struct.get_struc_name(tid)


def compat_choose_struc(title):
    """Prompt the user to pick a struct. Returns a tid, or None."""
    if IDA9:
        tif = ida_typeinf.tinfo_t()
        if not ida_kernwin.choose_struct(tif, title):
            return None
        return tif.get_tid()

    result = ida_kernwin.choose_struc(title)
    if result is None:
        return None
    return result.id


def compat_get_procname():
    if IDA9:
        return idaapi.inf_get_procname()
    return idaapi.get_inf_structure().procname
