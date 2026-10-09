"""Static receipt restrictions for the future-only launcher; no subprocess."""
import unittest
from pathlib import Path
SOURCE=(Path(__file__).resolve().parents[2]/"docs/security/phase2h/single_haos_guest.py")
class FutureReceiptTests(unittest.TestCase):
    def test_no_dynamic_exception_classes(self):
        s=SOURCE.read_text()
        self.assertNotIn("type(e).__name__",s)
        self.assertNotIn("type(exc).__name__",s)
        self.assertIn('BLOCKED_EXCEPTION',s)
    def test_supervisor_version_numeric_or_not_verified(self):
        s=SOURCE.read_text()
        self.assertIn('re.fullmatch',s)
        self.assertIn('20[0-9]{2}',s)
        self.assertIn('NOT_VERIFIED',s)
    def test_guest_acceptance_still_fail_closed(self):
        s=SOURCE.read_text()
        self.assertIn('return 6',s)
        self.assertIn('BLOCKED_INCOMPLETE_16_CASES',s)
if __name__=="__main__":unittest.main()
