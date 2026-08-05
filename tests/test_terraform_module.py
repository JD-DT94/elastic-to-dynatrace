"""The generated Terraform must drop into an existing repository unchanged.

The structural tests here encode the two rules that decide whether it does:
a module directory may hold exactly one `terraform {}` block, and a child module
must not configure a provider (that also makes it incompatible with `count`,
`for_each` and `depends_on` on the module itself).

Where the `terraform` CLI is installed the suite goes further and runs the real
`fmt -check`, `init` and `validate`, because the schema is the provider's to
define and guessing at it is how you ship HCL that applies cleanly and
configures the wrong thing.
"""

import json
import shutil
import subprocess

import pytest

from e2d.migrate import run_migration
from e2d.terraform.module import Resource, TerraformModule

HAS_TERRAFORM = shutil.which("terraform") is not None
requires_terraform = pytest.mark.skipif(not HAS_TERRAFORM,
                                        reason="terraform CLI not installed")

HEALTH_RULES = [
    {"name": "Checkout slow", "enabled": True,
     "affects": {"affectedEntityType": "BUSINESS_TRANSACTION_PERFORMANCE"},
     "evalCriterias": {"criticalCriteria": {"conditionAggregationType": "ANY", "conditions": [
         {"name": "ART", "evalDetail": {
             "metricPath": "Overall Application Performance|Average Response Time (ms)",
             "metricEvalDetail": {"metricEvalDetailType": "SPECIFIC_TYPE",
                                  "compareCondition": "GREATER_THAN",
                                  "compareValue": 2000}}}]}}},
    # same slug once sanitised — must not produce a duplicate identifier
    {"name": "Checkout  Slow", "enabled": True,
     "affects": {"affectedEntityType": "BUSINESS_TRANSACTION_PERFORMANCE"},
     "evalCriterias": {"criticalCriteria": {"conditionAggregationType": "ANY", "conditions": [
         {"name": "Calls", "evalDetail": {
             "metricPath": "Overall Application Performance|Calls per Minute",
             "metricEvalDetail": {"metricEvalDetailType": "SPECIFIC_TYPE",
                                  "compareCondition": "LESS_THAN",
                                  "compareValue": 10}}}]}}},
]

COLLECTORS = {"dataGathererConfigs": [
    {"name": "userId", "dataGathererType": "HTTP", "parameters": ["userId"],
     "headers": ["X-Tenant"], "cookies": ["session_id"]},
    {"name": "orderTotal", "dataGathererType": "METHOD_INVOCATION",
     "className": "com.shop.OrderService", "methodName": "checkout"},
]}

LOGSTASH = ('input { beats { port => 5044 } }\n'
            'filter { grok { match => { "message" => "%{IPORHOST:clientip}" } } }\n'
            'output { elasticsearch { hosts => ["es:9200"] } }\n')


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    root = tmp_path_factory.mktemp("tfrun")
    indir = root / "in"
    indir.mkdir()
    (indir / "rules.json").write_text(json.dumps(HEALTH_RULES), encoding="utf-8")
    (indir / "collectors.json").write_text(json.dumps(COLLECTORS), encoding="utf-8")
    (indir / "web.conf").write_text(LOGSTASH, encoding="utf-8")
    out = root / "out"
    summary = run_migration(str(indir), str(out))
    return summary, out / "terraform"


def _module_hcl(tf_dir) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(tf_dir.rglob("*.tf"))
                     if "example-root" not in str(p))


# --- structure ---------------------------------------------------------------- #

def test_module_has_the_expected_files(built):
    _, tf = built
    for name in ("versions.tf", "variables.tf", "outputs.tf", "README.md"):
        assert (tf / name).exists(), name
    assert (tf / "example-root" / "main.tf").exists()


def test_exactly_one_terraform_block_in_the_module(built):
    """Several root modules merged into one config fail to init."""
    _, tf = built
    assert _module_hcl(tf).count("terraform {") == 1


def test_module_declares_provider_requirements(built):
    _, tf = built
    hcl = _module_hcl(tf)
    assert "required_providers" in hcl
    assert "dynatrace-oss/dynatrace" in hcl


def test_module_configures_no_provider(built):
    """A provider block in a child module breaks count/for_each/depends_on."""
    _, tf = built
    assert 'provider "dynatrace"' not in _module_hcl(tf)


def test_example_root_does_configure_a_provider(built):
    """...but the example root must, or it cannot be applied."""
    _, tf = built
    root = (tf / "example-root" / "main.tf").read_text(encoding="utf-8")
    assert 'provider "dynatrace" {}' in root
    assert 'source = "../"' in root


def test_resource_identifiers_are_unique(built):
    import re
    _, tf = built
    ids = re.findall(r'^resource "([\w]+)" "([\w]+)"', _module_hcl(tf), re.M)
    assert ids, "no resources generated"
    assert len(ids) == len(set(ids)), "duplicate resource identifiers"


def test_titles_go_through_the_name_prefix_variable(built):
    _, tf = built
    assert "${var.name_prefix}" in _module_hcl(tf)


def test_detectors_are_created_disabled_by_default(built):
    _, tf = built
    detectors = (tf / "detectors.tf").read_text(encoding="utf-8")
    assert "enabled     = var.detectors_enabled" in detectors
    variables = (tf / "variables.tf").read_text(encoding="utf-8")
    assert "default     = false" in variables


def test_method_collectors_are_not_emitted_as_resources(built):
    """A method rule built from guesses applies cleanly and captures nothing."""
    _, tf = built
    attrs = (tf / "request_attributes.tf").read_text(encoding="utf-8")
    assert "userid" in attrs                 # HTTP collector converted
    assert "ordertotal" not in attrs         # method collector deliberately absent
    assert "methods {" not in attrs


def test_cookie_capture_uses_a_header_and_regex(built):
    _, tf = built
    attrs = (tf / "request_attributes.tf").read_text(encoding="utf-8")
    assert 'source                         = "REQUEST_HEADER"' in attrs
    assert "value_extractor_regex" in attrs


def test_collision_gets_a_suffix_not_an_overwrite():
    module = TerraformModule()
    first = module.add(Resource("dynatrace_x", "Checkout slow", "  a = 1"))
    second = module.add(Resource("dynatrace_x", "Checkout  Slow", "  a = 2"))
    assert first == "checkout_slow"
    assert second == "checkout_slow_2"
    assert len(module.resources) == 2


# --- the real thing ------------------------------------------------------------ #

@requires_terraform
def test_generated_hcl_is_already_formatted(built):
    _, tf = built
    proc = subprocess.run(["terraform", "fmt", "-check", "-recursive", str(tf)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, f"needs fmt:\n{proc.stdout}"


@requires_terraform
def test_terraform_init_and_validate_pass(built):
    """The provider owns the schema; only it can confirm the HCL is right."""
    _, tf = built
    root = tf / "example-root"
    init = subprocess.run(
        ["terraform", "init", "-backend=false", "-input=false", "-no-color"],
        cwd=str(root), capture_output=True, text=True)
    assert init.returncode == 0, init.stderr or init.stdout

    validate = subprocess.run(["terraform", "validate", "-no-color"], cwd=str(root),
                              capture_output=True, text=True)
    assert validate.returncode == 0, validate.stdout or validate.stderr
