from .. import utils

def modscan(args):
    """
    Plugin to list loaded modules.
    """
    output = utils.run_volatility_command("windows.modscan.ModScan", args.file)
    parsed_output = utils.parse_modscan(output)
    for item in parsed_output:
        print(item)

def register():
    """
    Registers the plugin with the main application.
    """
    return {
        "modscan": modscan
    }
