"""Filter legacy modules out of direct pip/wheel builds as well as release builds."""

from setuptools.command.build_py import build_py

MODULES = {
    "tooluseproxy": {
        "__init__",
        "__main__",
        "app",
        "paths",
        "log_viewer",
        "viewer_process",
        "authority_state",
        "authority_admin",
    },
    "tooluseproxy.integrations": {"__init__", "activation", "authority"},
}


class RuntimeBuildPy(build_py):
    def find_package_modules(self, package, package_dir):
        found = super().find_package_modules(package, package_dir)
        return [item for item in found if package not in MODULES or item[1] in MODULES[package]]
