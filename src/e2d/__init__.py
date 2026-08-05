"""Migration assistant (e2d): convert Elastic and AppDynamics configuration
into Dynatrace equivalents.

The `e2d` package name predates AppDynamics support and is kept so existing
imports, scripts and the CLI entry point keep working.

Public API:
    from e2d import translate_esql
    result = translate_esql("FROM logs-* | WHERE level == \"ERROR\" | LIMIT 10")
    print(result.dql)
    print(result.warnings)
"""

from e2d.esql.translator import translate_esql, EsqlTranslationResult

__all__ = ["translate_esql", "EsqlTranslationResult"]
__version__ = "0.2.0"
