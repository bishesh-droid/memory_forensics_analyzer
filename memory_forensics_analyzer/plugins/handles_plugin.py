from ..core.engine import ForensicsEngine


def handles(args, engine: ForensicsEngine = None):
    if engine:
        result = engine.run_plugin("windows.handles.Handles")
        return result.rows
    from .. import utils
    output = utils.run_volatility_command("windows.handles.Handles", args.file)
    return utils.parse_output(output, "handles")


def register():
    return {"handles": handles}
