from ..core.engine import ForensicsEngine


def envars(args, engine: ForensicsEngine = None):
    if engine:
        result = engine.run_plugin("windows.envars.Envars")
        return result.rows
    from .. import utils
    output = utils.run_volatility_command("windows.envars.Envars", args.file)
    return utils.parse_output(output, "envars")


def register():
    return {"envars": envars}
