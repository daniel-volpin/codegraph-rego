import json
from unittest.mock import patch

import pytest

from scripts.search import hybrid_code_search


def test_cli_uses_the_canonical_search_generation(capsys):
    key = "workspace@revision:Demo.java#method"
    contexts = [[{"method": "demo.Demo.method()", "neighbors": []}]]
    with patch("codegraph.search.service.run_search", return_value=([key], contexts)) as search:
        assert hybrid_code_search.main(["example", "-k", "2", "--json"]) == 0
    search.assert_called_once_with("example", k=2)
    assert json.loads(capsys.readouterr().out) == {"matches": [key], "contexts": contexts}


def test_cli_rejects_legacy_map_selection():
    with pytest.raises(SystemExit):
        hybrid_code_search.parse_args(["example", "--legacy-signature-map", "old.json"])


def test_text_results_preserve_identity_and_display(capsys):
    hybrid_code_search._print_results(
        ["workspace@revision:Demo.java#method"],
        [[{
            "method": "demo.Demo.method()",
            "neighbors": [{"type": "Method", "id": "other-key", "display": "demo.Other.call()"}],
        }]],
        False,
    )
    output = capsys.readouterr().out
    assert "workspace@revision:Demo.java#method" in output
    assert "demo.Demo.method()" in output
    assert "demo.Other.call()" in output
    assert "other-key" in output
