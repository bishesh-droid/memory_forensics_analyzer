from ..core.engine import ForensicsEngine


def linux_pslist(args, engine: ForensicsEngine = None):
    if engine:
        return engine.run_plugin("linux.pslist.PsList").rows
    from .. import utils
    output = utils.run_volatility_command("linux.pslist.PsList", args.file)
    return utils.parse_output(output, "linux_pslist")


def linux_pstree(args, engine: ForensicsEngine = None):
    if engine:
        return engine.run_plugin("linux.pstree.PsTree").rows
    from .. import utils
    output = utils.run_volatility_command("linux.pstree.PsTree", args.file)
    return utils.parse_output(output, "linux_pstree")


def linux_lsmod(args, engine: ForensicsEngine = None):
    if engine:
        return engine.run_plugin("linux.lsmod.Lsmod").rows
    from .. import utils
    output = utils.run_volatility_command("linux.lsmod.Lsmod", args.file)
    return utils.parse_output(output, "linux_lsmod")


def linux_bash(args, engine: ForensicsEngine = None):
    if engine:
        return engine.run_plugin("linux.bash.Bash").rows
    from .. import utils
    output = utils.run_volatility_command("linux.bash.Bash", args.file)
    return utils.parse_output(output, "linux_bash")


def linux_sockstat(args, engine: ForensicsEngine = None):
    if engine:
        return engine.run_plugin("linux.sockstat.Sockstat").rows
    from .. import utils
    output = utils.run_volatility_command("linux.sockstat.Sockstat", args.file)
    return utils.parse_output(output, "linux_sockstat")


def linux_check_syscall(args, engine: ForensicsEngine = None):
    if engine:
        return engine.run_plugin("linux.check_syscall.Check_syscall").rows
    from .. import utils
    output = utils.run_volatility_command("linux.check_syscall.Check_syscall", args.file)
    return utils.parse_output(output, "linux_check_syscall")


def register():
    return {
        "linux_pslist": linux_pslist,
        "linux_pstree": linux_pstree,
        "linux_lsmod": linux_lsmod,
        "linux_bash": linux_bash,
        "linux_sockstat": linux_sockstat,
        "linux_check_syscall": linux_check_syscall,
    }
