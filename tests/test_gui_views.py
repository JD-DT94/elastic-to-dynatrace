"""Platform tabs in both GUIs: home, Elastic, AppDynamics.

The two pages are large inline blobs with no build step, so a typo in a view
class silently hides a panel forever. These tests pin the wiring: the switch
attribute, one section per platform, and the invariant that the tab only
changes what is on screen — the converter itself is shared and never gated.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site" / "index.html"
SERVER = ROOT / "src" / "e2d" / "web" / "server.py"


def _server_html() -> str:
    text = SERVER.read_text(encoding="utf-8")
    start = text.lower().find("<!doctype html")
    end = text.rfind("</html>")
    assert start != -1 and end != -1, "could not locate the inline page in server.py"
    return text[start:end + len("</html>")]


PAGES = {"browser": SITE.read_text(encoding="utf-8"), "local": _server_html()}


@pytest.mark.parametrize("name", sorted(PAGES))
def test_page_has_the_three_tabs(name):
    html = PAGES[name]
    assert 'id="tabs"' in html
    for view in ("home", "elastic", "appd"):
        assert f'data-view="{view}"' in html, f"{name} is missing the {view} tab"
    # the switch itself
    assert 'id="app"' in html and 'data-plat="home"' in html


@pytest.mark.parametrize("name", sorted(PAGES))
def test_home_offers_a_platform_choice(name):
    html = PAGES[name]
    assert 'class="picker' in html
    # both platform cards, each acting as a way into its view
    cards = re.findall(r'class="pcard"\s+data-view="(\w+)"', html)
    assert set(cards) == {"elastic", "appd"}, cards


@pytest.mark.parametrize("name", sorted(PAGES))
def test_every_view_class_is_backed_by_a_css_rule(name):
    html = PAGES[name]
    used = set(re.findall(r"\bv-(home|elastic|appd|conv)\b", html))
    assert used == {"home", "elastic", "appd", "conv"}, used
    # each one must be revealed by the data-plat switch, or it is dead markup
    for cls in sorted(used):
        assert re.search(rf'\[data-plat="\w+"\]\s+\.v-{cls}\b', html), \
            f"{name}: .v-{cls} is used but never revealed by a [data-plat] rule"


@pytest.mark.parametrize("name", sorted(PAGES))
def test_converter_is_shared_not_duplicated(name):
    html = PAGES[name]
    # exactly one drop zone and one file input — duplicating them per platform
    # would split the upload state in two
    assert html.count('id="drop"') == 1
    assert len(re.findall(r'type="file"', html)) == 1
    # and it is marked shared, not owned by one platform
    assert "v v-conv" in html


@pytest.mark.parametrize("name", sorted(PAGES))
def test_platform_specific_panels_are_scoped(name):
    html = PAGES[name]
    # AppD examples must exist and sit in the AppD view
    for eg in ("appdrule", "appddash", "appdinv"):
        assert f'data-eg="{eg}"' in html
    appd_block = html[html.index('class="v v-appd"'):]
    assert 'data-eg="appdrule"' in appd_block[:4000]


def test_local_gui_keeps_elastic_only_panels_off_the_appd_tab():
    html = PAGES["local"]
    # live pull and backfill are Elasticsearch-specific; AppD has no equivalent
    for panel in ('id="pull-card"', 'id="backfill-card"', 'id="mapping-card"'):
        idx = html.index(panel)
        opening = html.rfind("<details", 0, idx)
        assert "v-elastic" in html[opening:idx + len(panel)], \
            f"{panel} must be scoped to the Elastic view"


def test_hidden_results_panel_stays_hidden_when_a_view_opens():
    """`display:revert` on a view would otherwise unhide an empty report."""
    for name, html in PAGES.items():
        assert re.search(r"\[hidden\]\.v|\.card\.hide\.v-conv", html), \
            f"{name}: no guard keeping an empty results panel hidden"
