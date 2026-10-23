#!/usr/bin/env python3
"""Minimaler Check: Blue-Soldaten, ein Kolonie-Lauf, Route /blue."""
from __future__ import annotations

import unittest

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_bluequeen")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
