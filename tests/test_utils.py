import unittest
from unittest.mock import patch
from memory_forensics_analyzer import utils

class TestUtils(unittest.TestCase):

    def test_parse_pslist(self):
        pslist_output = """
PID   PPID   ImageFileName      Offset(V)          Threads   Handles   SessionId   Wow64   CreateTime             ExitTime
----- ------ ------------------ ------------------ --------- --------- ----------- ------- ---------------------- ----------------------
4     0      System             0x8291a920         53        380       ------      0       2026-01-04 12:00:00    
284   4      smss.exe           0x82a0b3e0         3         29        ------      0       2026-01-04 12:00:00    
"""
        parsed = utils.parse_pslist(pslist_output)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]['ImageFileName'], 'System')
        self.assertEqual(parsed[0]['PID'], '4')
        self.assertEqual(parsed[1]['ImageFileName'], 'smss.exe')
        self.assertEqual(parsed[1]['PID'], '284')

    def test_parse_netscan(self):
        netscan_output = """
Offset             Proto  LocalAddr              LocalPort  ForeignAddr            ForeignPort  State   PID    Owner          Created
------------------ ------ ---------------------- ---------- ---------------------- ------------ ------- ------ -------------- ----------------------
0xffffa10001234560 TCP    0.0.0.0                135        0.0.0.0                0            LISTEN  704    svchost.exe    2023-10-26 10:05:12
0xffffa100012346a0 TCP    0.0.0.0                445        0.0.0.0                0            LISTEN  4      System         2023-10-26 10:05:12
"""
        parsed = utils.parse_netscan(netscan_output)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]['Proto'], 'TCP')
        self.assertEqual(parsed[0]['Owner'], 'svchost.exe')
        self.assertEqual(parsed[1]['LocalAddr'], '0.0.0.0')
        self.assertEqual(parsed[1]['PID'], '4')

    def test_parse_modscan(self):
        modscan_output = """
Offset             Size       Base               File                 Path
------------------ ---------- ------------------ -------------------- ----------------------------------------------------
0xfffff80003210000 0x1a000    0xfffff80003210000 ntoskrnl.exe         C:\\Windows\\system32\\ntoskrnl.exe
0xfffff80003400000 0x10000    0xfffff80003400000 hal.dll              C:\\Windows\\system32\\hal.dll
"""
        parsed = utils.parse_modscan(modscan_output)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]['File'], 'ntoskrnl.exe')
        self.assertEqual(parsed[0]['Size'], '0x1a000')
        self.assertEqual(parsed[1]['Path'], 'C:\\Windows\\system32\\hal.dll')
        self.assertEqual(parsed[1]['Offset'], '0xfffff80003400000')

    @patch('subprocess.run')
    def test_run_volatility_command(self, mock_run):
        mock_run.return_value.stdout = "Volatility output"
        output = utils.run_volatility_command("pslist", "memdump.mem")
        self.assertEqual(output, "Volatility output")

if __name__ == '__main__':
    unittest.main()
