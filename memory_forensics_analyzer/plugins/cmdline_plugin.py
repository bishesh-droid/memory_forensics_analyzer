from ..core.engine import ForensicsEngine


def cmdline(args, engine: ForensicsEngine = None):
    if engine:
        result = engine.run_plugin("windows.cmdline.CmdLine")
        return result.rows
    from .. import utils
    output = utils.run_volatility_command("windows.cmdline.CmdLine", args.file)
    return utils.parse_output(output, "cmdline")


def register():
    return {"cmdline": cmdline}
