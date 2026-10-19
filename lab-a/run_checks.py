"""Run both test locations; plain unittest discovery misses tests/ in this project."""
import os
from pathlib import Path
import sys
import unittest


def main():
    root = Path(__file__).resolve().parent
    os.chdir(root)
    suite = unittest.TestSuite()
    for directory in (root, root / 'tests'):
        suite.addTests(unittest.TestLoader().discover(str(directory), pattern='test_*.py'))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() and result.testsRun else 1


if __name__ == '__main__':
    sys.exit(main())
