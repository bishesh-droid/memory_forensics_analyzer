from ..core.engine import ForensicsEngine


def callbacks(args, engine: ForensicsEngine = None):
    if engine:
        result = engine.run_plugin("windows.callbacks.Callbacks")
        return result.rows
    from .. import utils
    output = utils.run_volatility_command("windows.callbacks.Callbacks", args.file)
    return utils.parse_output(output, "callbacks")


def register():
    return {"callbacks": callbacks}
