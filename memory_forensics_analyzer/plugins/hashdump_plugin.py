from ..core.engine import ForensicsEngine


def hashdump(args, engine: ForensicsEngine = None):
    if engine:
        result = engine.run_plugin("windows.hashdump.Hashdump")
        return result.rows
    from .. import utils
    output = utils.run_volatility_command("windows.hashdump.Hashdump", args.file)
    return utils.parse_output(output, "hashdump")


def register():
    return {"hashdump": hashdump}
