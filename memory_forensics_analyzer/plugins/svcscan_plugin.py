from ..core.engine import ForensicsEngine


def svcscan(args, engine: ForensicsEngine = None):
    if engine:
        result = engine.run_plugin("windows.svcscan.SvcScan")
        return result.rows
    from .. import utils
    output = utils.run_volatility_command("windows.svcscan.SvcScan", args.file)
    return utils.parse_output(output, "svcscan")


def register():
    return {"svcscan": svcscan}
