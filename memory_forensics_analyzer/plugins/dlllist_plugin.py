from ..core.engine import ForensicsEngine


def dlllist(args, engine: ForensicsEngine = None):
    if engine:
        result = engine.run_plugin("windows.dlllist.DllList")
        return result.rows
    from .. import utils
    output = utils.run_volatility_command("windows.dlllist.DllList", args.file)
    return utils.parse_output(output, "dlllist")


def register():
    return {"dlllist": dlllist}
