from ..core.engine import ForensicsEngine


def filescan(args, engine: ForensicsEngine = None):
    if engine:
        result = engine.run_plugin("windows.filescan.FileScan")
        return result.rows
    from .. import utils
    output = utils.run_volatility_command("windows.filescan.FileScan", args.file)
    return utils.parse_output(output, "filescan")


def register():
    return {"filescan": filescan}
