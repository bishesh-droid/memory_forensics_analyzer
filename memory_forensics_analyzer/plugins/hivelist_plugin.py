from ..core.engine import ForensicsEngine


def hivelist(args, engine: ForensicsEngine = None):
    if engine:
        result = engine.run_plugin("windows.registry.hivelist.HiveList")
        return result.rows
    from .. import utils
    output = utils.run_volatility_command("windows.registry.hivelist.HiveList", args.file)
    return utils.parse_output(output, "hivelist")


def printkey(args, engine: ForensicsEngine = None):
    extra = []
    if hasattr(args, "key") and args.key:
        extra = ["--key", args.key]
    if engine:
        result = engine.run_plugin("windows.registry.printkey.PrintKey", extra)
        return result.rows
    from .. import utils
    cmd = "windows.registry.printkey.PrintKey"
    output = utils.run_volatility_command(cmd, args.file)
    return utils.parse_output(output, "printkey")


def register():
    return {"hivelist": hivelist, "printkey": printkey}
