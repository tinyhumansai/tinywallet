"""Regression fixtures for implementation edges and registry identity."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("boundary", Path(__file__).with_name("check-bus-boundaries.py"))
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)


def metadata(name, kind=None, source=boundary.REGISTRY):
    return {"packages": [{"id": "root", "name": "tinywallet-bus"}, {"id": "dependency", "name": name, "source": source}], "resolve": {"nodes": [{"id": "root", "deps": [{"pkg": "dependency", "dep_kinds": [{"kind": kind}]}]}, {"id": "dependency", "deps": []}]}}


class ContractBoundaryTests(unittest.TestCase):
    def test_registry_serde_is_allowed(self):
        self.assertEqual(boundary.audit(metadata("serde")), [])

    def test_implementation_is_rejected_even_as_a_build_dependency(self):
        for kind in (None, "build"):
            self.assertEqual(boundary.audit(metadata("tinywallet-crypto", kind)), ["tinywallet-bus -> tinywallet-crypto"])

    def test_dev_dependencies_are_exempt(self):
        self.assertEqual(boundary.audit(metadata("tinywallet-crypto", "dev")), [])

    def test_local_package_cannot_impersonate_serde(self):
        self.assertTrue(boundary.audit(metadata("serde", source=None)))


if __name__ == "__main__":
    unittest.main()
