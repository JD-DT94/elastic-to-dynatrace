"""elastic-to-dynatrace (e2d): convert Elastic artifacts to Dynatrace.

Public API:
    from e2d import translate_esql
    result = translate_esql("FROM logs-* | WHERE level == \"ERROR\" | LIMIT 10")
    print(result.dql)
    print(result.warnings)
"""

from e2d.esql.translator import translate_esql, EsqlTranslationResult

__all__ = ["translate_esql", "EsqlTranslationResult"]
__version__ = "0.1.0"
