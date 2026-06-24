from ..core.engine import ForensicsEngine


def malfind(args, engine: ForensicsEngine = None):
    if engine:
        result = engine.run_plugin("windows.malfind.Malfind")
        return result.rows
    from .. import utils
    output = utils.run_volatility_command("windows.malfind.Malfind", args.file)
    return utils.parse_output(output, "malfind")


def register():
    return {"malfind": malfind}
