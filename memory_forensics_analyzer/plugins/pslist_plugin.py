from .. import utils

def pslist(args):
    """
    Plugin to list processes.
    """
    output = utils.run_volatility_command("windows.pslist.PsList", args.file)
    parsed_output = utils.parse_pslist(output)
    for item in parsed_output:
        print(item)

def register():
    """
    Registers the plugin with the main application.
    """
    return {
        "pslist": pslist
    }
