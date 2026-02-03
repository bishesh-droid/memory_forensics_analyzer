import argparse
import sys
import pkgutil
import importlib.util
import os
from . import utils
from . import plugins

def load_plugins():
    plugin_commands = {}
    for importer, modname, ispkg in pkgutil.iter_modules(plugins.__path__):
        plugin_path = os.path.join(plugins.__path__[0], modname + ".py")
        spec = importlib.util.spec_from_file_location(modname, plugin_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if hasattr(module, 'register'):
            plugin_commands.update(module.register())
    return plugin_commands

def main():
    # Discover and load plugins
    plugin_commands = load_plugins()

    parser = argparse.ArgumentParser(description="Memory Forensics Analyzer")
    parser.add_argument("-f", "--file", required=True, help="Path to the memory dump file")
    parser.add_argument("-c", "--command", required=True, help="Command to run")
    args = parser.parse_args()

    if args.command in plugin_commands:
        plugin_commands[args.command](args)
    else:
        print(f"Command not found: {args.command}")
        print("Available commands:")
        for cmd in plugin_commands.keys():
            print(f"  - {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()