"""Sandboxed evaluator for rule expressions.

Rules are written as small Python expressions (`cfg.get('public') is True`). Evaluating them
with eval() and an empty __builtins__ is NOT a sandbox — `().__class__.__mro__[1].__subclasses__()`
walks out of it. Rules are config, config gets edited, so the expression is parsed and every
node is checked against an allow-list before it is ever compiled:

  * names:      only the variables the engine provides plus a few pure helpers
  * attributes: only read-only dict/str methods (get, values, startswith, ...); no dunders
  * calls:      only those helpers / methods; no keyword splats
  * no lambdas, no imports, no assignments, no f-strings, no walrus
"""

from __future__ import annotations

import ast
from typing import Any

SAFE_FUNCS = {"any": any, "all": all, "len": len, "str": str, "int": int, "float": float, "bool": bool,
              "min": min, "max": max, "sum": sum, "sorted": sorted, "set": set}
SAFE_METHODS = {"get", "values", "keys", "items", "startswith", "endswith", "lower", "upper", "split", "strip"}
_ALLOWED_NODES = (
    ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.USub, ast.BinOp, ast.Add, ast.Sub,
    ast.Mult, ast.Div, ast.Mod, ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Is,
    ast.IsNot, ast.In, ast.NotIn, ast.Name, ast.Load, ast.Store, ast.Constant, ast.Subscript, ast.Call,
    ast.Attribute, ast.Tuple, ast.List, ast.Set, ast.Dict, ast.IfExp, ast.GeneratorExp, ast.ListComp,
    ast.SetComp, ast.comprehension,
)
MAX_LEN = 600


class UnsafeExpression(ValueError):
    pass


def compile_rule(expr: str, variables: set[str], name: str = "<rule>"):
    """Validate `expr` and return a code object. Raises UnsafeExpression on anything off-list."""
    if len(expr) > MAX_LEN:
        raise UnsafeExpression(f"{name}: expression too long")
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise UnsafeExpression(f"{name}: {e.msg}") from e
    bound: set[str] = set()                      # comprehension targets
    for node in ast.walk(tree):
        if isinstance(node, ast.comprehension):
            for t in ast.walk(node.target):
                if isinstance(t, ast.Name):
                    bound.add(t.id)
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise UnsafeExpression(f"{name}: {type(node).__name__} is not allowed in a rule")
        if isinstance(node, ast.Name):
            if node.id.startswith("_") or node.id not in (variables | bound | set(SAFE_FUNCS)):
                raise UnsafeExpression(f"{name}: unknown name {node.id!r}")
        elif isinstance(node, ast.Attribute):
            if node.attr not in SAFE_METHODS:
                raise UnsafeExpression(f"{name}: attribute {node.attr!r} is not allowed")
        elif isinstance(node, ast.Call):
            f = node.func
            ok = (isinstance(f, ast.Name) and f.id in SAFE_FUNCS) or (isinstance(f, ast.Attribute) and f.attr in SAFE_METHODS)
            if not ok or any(k.arg is None for k in node.keywords):
                raise UnsafeExpression(f"{name}: call is not allowed")
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, (bytes, complex)) or (isinstance(node.value, str) and "__" in node.value):
                raise UnsafeExpression(f"{name}: constant is not allowed")
    return compile(tree, name, "eval")


def evaluate(code, env: dict[str, Any]) -> Any:
    # env goes in globals: names used inside a comprehension body are resolved there, not in locals.
    return eval(code, {"__builtins__": {}, **SAFE_FUNCS, **env})  # noqa: S307 — AST was allow-listed above
