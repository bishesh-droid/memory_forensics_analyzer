from ..core.engine import ForensicsEngine


def ssdt(args, engine: ForensicsEngine = None):
    if engine:
        result = engine.run_plugin("windows.ssdt.SSDT")
        return result.rows
    from .. import utils
    output = utils.run_volatility_command("windows.ssdt.SSDT", args.file)
    return utils.parse_output(output, "ssdt")


def register():
    return {"ssdt": ssdt}
