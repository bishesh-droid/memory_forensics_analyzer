from ..core.engine import ForensicsEngine


def psscan(args, engine: ForensicsEngine = None):
    if engine:
        result = engine.run_plugin("windows.psscan.PsScan")
        return result.rows
    from .. import utils
    output = utils.run_volatility_command("windows.psscan.PsScan", args.file)
    return utils.parse_output(output, "psscan")


def register():
    return {"psscan": psscan}
