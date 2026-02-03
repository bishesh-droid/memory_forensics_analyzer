import unittest
from unittest.mock import patch, MagicMock
from memory_forensics_analyzer.main import main

class TestMain(unittest.TestCase):

    @patch('memory_forensics_analyzer.main.argparse.ArgumentParser')
    @patch('memory_forensics_analyzer.main.load_plugins')
    def test_main_with_valid_command(self, mock_load_plugins, mock_parser):
        # Mock the command-line arguments
        args = MagicMock()
        args.file = "memory.dmp"
        args.command = "pslist"
        mock_parser.return_value.parse_args.return_value = args

        # Mock the plugin commands
        mock_pslist = MagicMock()
        mock_load_plugins.return_value = {"pslist": mock_pslist}

        main()
        mock_pslist.assert_called_with(args)

    @patch('memory_forensics_analyzer.main.argparse.ArgumentParser')
    @patch('memory_forensics_analyzer.main.load_plugins')
    @patch('builtins.print')
    @patch('sys.exit')
    def test_main_with_invalid_command(self, mock_exit, mock_print, mock_load_plugins, mock_parser):
        # Mock the command-line arguments
        args = MagicMock()
        args.file = "memory.dmp"
        args.command = "invalid_command"
        mock_parser.return_value.parse_args.return_value = args

        # Mock the plugin commands
        mock_load_plugins.return_value = {"pslist": lambda: None}

        main()
        mock_print.assert_any_call("Command not found: invalid_command")
        mock_print.assert_any_call("Available commands:")
        mock_print.assert_any_call("  - pslist")
        mock_exit.assert_called_with(1)

if __name__ == '__main__':
    unittest.main()