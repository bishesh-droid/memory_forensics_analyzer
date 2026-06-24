from ..core.engine import ForensicsEngine


def driverirp(args, engine: ForensicsEngine = None):
    if engine:
        result = engine.run_plugin("windows.driverirp.DriverIrp")
        return result.rows
    from .. import utils
    output = utils.run_volatility_command("windows.driverirp.DriverIrp", args.file)
    return utils.parse_output(output, "driverirp")


def register():
    return {"driverirp": driverirp}
