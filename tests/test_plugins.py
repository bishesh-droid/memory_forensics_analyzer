import unittest
from unittest.mock import patch, MagicMock
from memory_forensics_analyzer.plugins import pslist_plugin, netscan_plugin, modscan_plugin

class TestPlugins(unittest.TestCase):

    def test_pslist_plugin(self):
        args = MagicMock()
        args.file = "memdump.mem"
        with patch('memory_forensics_analyzer.utils.run_volatility_command') as mock_run, \
             patch('memory_forensics_analyzer.utils.parse_pslist') as mock_parse:
            mock_run.return_value = "pslist output"
            mock_parse.return_value = [{"PID": "4", "ImageFileName": "System"}]
            pslist_plugin.pslist(args)
            mock_run.assert_called_with("windows.pslist.PsList", "memdump.mem")
            mock_parse.assert_called_with("pslist output")

    def test_netscan_plugin(self):
        args = MagicMock()
        args.file = "memdump.mem"
        with patch('memory_forensics_analyzer.utils.run_volatility_command') as mock_run, \
             patch('memory_forensics_analyzer.utils.parse_netscan') as mock_parse:
            mock_run.return_value = "netscan output"
            mock_parse.return_value = [{"Proto": "TCP", "Owner": "svchost.exe"}]
            netscan_plugin.netscan(args)
            mock_run.assert_called_with("windows.netscan.NetScan", "memdump.mem")
            mock_parse.assert_called_with("netscan output")

    def test_modscan_plugin(self):
        args = MagicMock()
        args.file = "memdump.mem"
        with patch('memory_forensics_analyzer.utils.run_volatility_command') as mock_run, \
             patch('memory_forensics_analyzer.utils.parse_modscan') as mock_parse:
            mock_run.return_value = "modscan output"
            mock_parse.return_value = [{"File": "ntoskrnl.exe", "Path": "C:\\Windows\\system32\\ntoskrnl.exe"}]
            modscan_plugin.modscan(args)
            mock_run.assert_called_with("windows.modscan.ModScan", "memdump.mem")
            mock_parse.assert_called_with("modscan output")

if __name__ == '__main__':
    unittest.main()
