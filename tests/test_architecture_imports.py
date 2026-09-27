"""Architecture and import boundary tests.

Verifies Sections 23 and 56 requirements:
- Security engine must remain provider-agnostic.
- SecretDetector, PolicyEngine, RedactionEngine, DetectionResult, PolicyDecision
  must NOT import provider adapters or the providers package.
- Provider adapters may depend on normalized domain models.
- Proxy pipeline may depend on both provider adapters and security core.
"""

import ast
from pathlib import Path


def _get_imports(file_path: Path) -> list[str]:
    """Parse a python file and return all imported module names."""
    content = file_path.read_text(encoding="utf-8")
    tree = ast.parse(content, filename=str(file_path))
    imported_modules: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.append(node.module)

    return imported_modules


def test_detectors_do_not_import_providers() -> None:
    """Verify detector modules do not import provider adapters."""
    detectors_dir = Path("src/aifirewall/detectors")
    for py_file in detectors_dir.glob("*.py"):
        imports = _get_imports(py_file)
        for imp in imports:
            assert "aifirewall.providers" not in imp, (
                f"Architecture violation: {py_file} imports provider module '{imp}'"
            )


def test_policy_does_not_import_providers() -> None:
    """Verify policy modules do not import provider adapters."""
    policy_dir = Path("src/aifirewall/policy")
    for py_file in policy_dir.glob("*.py"):
        imports = _get_imports(py_file)
        for imp in imports:
            assert "aifirewall.providers" not in imp, (
                f"Architecture violation: {py_file} imports provider module '{imp}'"
            )


def test_transformation_does_not_import_providers() -> None:
    """Verify redaction/transformation modules do not import provider adapters."""
    transformation_dir = Path("src/aifirewall/transformation")
    for py_file in transformation_dir.glob("*.py"):
        imports = _get_imports(py_file)
        for imp in imports:
            assert "aifirewall.providers" not in imp, (
                f"Architecture violation: {py_file} imports provider module '{imp}'"
            )


def test_models_do_not_import_providers() -> None:
    """Verify domain models do not import provider adapters."""
    models_dir = Path("src/aifirewall/models")
    for py_file in models_dir.glob("*.py"):
        imports = _get_imports(py_file)
        for imp in imports:
            assert "aifirewall.providers" not in imp, (
                f"Architecture violation: {py_file} imports provider module '{imp}'"
            )


def test_core_does_not_import_providers() -> None:
    """Verify core types/errors do not import provider adapters."""
    core_dir = Path("src/aifirewall/core")
    for py_file in core_dir.glob("*.py"):
        imports = _get_imports(py_file)
        for imp in imports:
            assert "aifirewall.providers" not in imp, (
                f"Architecture violation: {py_file} imports provider module '{imp}'"
            )


def test_security_engine_instances_have_no_provider_dependencies() -> None:
    """Runtime check: security components have no provider references."""
    import sys

    from aifirewall.detectors.secret import SecretDetector
    from aifirewall.policy.engine import PolicyEngine
    from aifirewall.transformation.redaction import RedactionEngine

    sec_detector_mod = sys.modules[SecretDetector.__module__]
    policy_engine_mod = sys.modules[PolicyEngine.__module__]
    redaction_engine_mod = sys.modules[RedactionEngine.__module__]

    for mod, name in [
        (sec_detector_mod, "SecretDetector"),
        (policy_engine_mod, "PolicyEngine"),
        (redaction_engine_mod, "RedactionEngine"),
    ]:
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if hasattr(obj, "__module__") and obj.__module__:
                assert "aifirewall.providers" not in obj.__module__, (
                    f"Runtime violation: {name} has reference to {obj.__module__}"
                )
