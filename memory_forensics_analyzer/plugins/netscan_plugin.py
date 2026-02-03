from .. import utils

def netscan(args):
    """
    Plugin to list network connections.
    """
    output = utils.run_volatility_command("windows.netscan.NetScan", args.file)
    parsed_output = utils.parse_netscan(output)
    for item in parsed_output:
        print(item)

def register():
    """
    Registers the plugin with the main application.
    """
    return {
        "netscan": netscan
    }
