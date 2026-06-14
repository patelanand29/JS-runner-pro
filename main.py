import sys
import math
import re
import time
import datetime
import random
from pyjsparser import parse

# Give legitimate deep recursion some headroom, while staying well below
# where CPython's own C stack would actually fault (see FIX 7 / Vuln 2).
sys.setrecursionlimit(6000)

# ─── 1. MEMORY & EXCEPTIONS ───────────────────────────────────────────────────

class Environment:
    def __init__(self, parent=None):
        self.variables = {}
        self.parent = parent

    def set_var(self, name, value):
        self.variables[name] = value

    def get_var(self, name):
        if name in self.variables: return self.variables[name]
        if self.parent is not None: return self.parent.get_var(name)
        return None

class ReturnException(Exception):
    def __init__(self, value): self.value = value

class BreakException(Exception): pass
class ContinueException(Exception): pass

# FIX 5: Timeout exception
class TimeoutException(Exception): pass

# Module-level start time, set per run_js() call
_START_TIME = None
_TIMEOUT_SECONDS = 5.0

# FIX 7 (Vuln 2): explicit call-stack depth guard, reset per run_js() call.
# Infinite recursion (e.g. `function crash(){ return crash(); }`) will hit
# this LONG before the 5s wall-clock timeout or a raw Python RecursionError.
_CALL_DEPTH = 0
_MAX_CALL_DEPTH = 800

def _check_timeout():
    if _START_TIME is not None and (time.time() - _START_TIME) > _TIMEOUT_SECONDS:
        raise TimeoutException("Execution time limit exceeded (5s)")

# ─── 2. JS UTILITIES ──────────────────────────────────────────────────────────

def js_str(val):
    if val is None: return "undefined"
    if isinstance(val, bool): return str(val).lower()
    if isinstance(val, float):
        if math.isnan(val): return "NaN"
        if math.isinf(val): return "Infinity" if val > 0 else "-Infinity"
        if val.is_integer(): return str(int(val))
    if isinstance(val, list):
        return ",".join(js_str(x) for x in val)
    if isinstance(val, dict):
        return "[object Object]"
    return str(val)

def safe_math(op, l, r):
    if op == "+" and (isinstance(l, str) or isinstance(r, str)):
        return js_str(l) + js_str(r)
    try:
        lf = float(l) if l is not None and not isinstance(l, (list, dict)) else math.nan
        rf = float(r) if r is not None and not isinstance(r, (list, dict)) else math.nan
        if op == "+": return lf + rf
        if op == "-": return lf - rf
        if op == "*": return lf * rf
        if op == "/": return lf / rf if rf != 0 else (math.inf if lf > 0 else -math.inf)
        if op == "%": return lf % rf if rf != 0 else math.nan
    except:
        return math.nan

# FIX 1, FIX 3 & FIX 7/8: Rest parameters + `this` binding + recursion guard
def call_js_func(func_node, args_list, env, this_val=None):
    global _CALL_DEPTH

    # FIX 7 (Vuln 2): check the wall-clock budget on *every* call, not just
    # inside loops. This is what lets a recursive infinite loop like
    # `function crash(){ return crash(); }; crash();` get caught as a
    # TimeoutException instead of bypassing the loop-only checks entirely.
    _check_timeout()

    if not isinstance(func_node, dict) or "body" not in func_node:
        return None

    # FIX 7 (Vuln 2): bound the JS-level call-stack depth explicitly.
    # Pure infinite recursion has no per-call cost large enough to ever hit
    # the 5s timeout before it blows the Python interpreter's own stack
    # (RecursionError), which would crash the whole process. This guard
    # fires first, raising the same graceful TimeoutException.
    _CALL_DEPTH += 1
    if _CALL_DEPTH > _MAX_CALL_DEPTH:
        _CALL_DEPTH -= 1
        raise TimeoutException("Maximum call stack size exceeded")

    try:
        local_env = Environment(parent=env)

        # FIX 8 (Vuln 3): `this` binding.
        #   - Arrow functions (tagged `_is_arrow` by _tag_arrow_functions /
        #     the FunctionExpression evaluator below) NEVER take the
        #     caller-supplied `this_val`. Instead they use whatever `this`
        #     was captured lexically at the moment the arrow literal was
        #     created (`_captured_this`). If nothing was captured, `this`
        #     is left unresolved here and falls through to the enclosing
        #     scope via the Environment parent chain, just like real JS.
        #   - Regular functions keep the original dynamic `this` binding
        #     supplied by the call site (obj.method() -> this == obj).
        if func_node.get("_is_arrow"):
            lexical_this = func_node.get("_captured_this")
            if lexical_this is not None:
                local_env.set_var("this", lexical_this)
        elif this_val is not None:
            local_env.set_var("this", this_val)

        params = func_node.get("params", [])
        for i, param in enumerate(params):
            # FIX 1: Detect RestElement (the ...rest param)
            if param.get("type") == "RestElement":
                rest_name = param.get("argument", {}).get("name")
                if rest_name:
                    local_env.set_var(rest_name, args_list[i:])
                break
            p_name = param.get("name")
            local_env.set_var(p_name, args_list[i] if i < len(args_list) else None)

        body = func_node.get("body")
        try:
            if isinstance(body, dict) and body.get("type") == "BlockStatement":
                evaluate(body, local_env)
            elif body:
                return evaluate(body, local_env)
        except ReturnException as ret:
            return ret.value
        return None
    finally:
        _CALL_DEPTH -= 1

# ─── 3. JS-ACCURATE SLICE/SPLICE HELPERS ─────────────────────────────────────

# FIX 4: JavaScript-accurate array slicing
def js_array_slice(arr, arg0, arg1):
    n = len(arr)
    # Start index
    if arg0 is None:
        s = 0
    else:
        s = int(float(arg0))
        if s < 0: s = max(0, n + s)
        else: s = min(s, n)
    # End index
    if arg1 is None:
        e = n
    else:
        e = int(float(arg1))
        if e < 0: e = max(0, n + e)
        else: e = min(e, n)
    return arr[s:e]

# FIX 4: JavaScript-accurate string slicing
def js_string_slice(s, arg0, arg1):
    n = len(s)
    if arg0 is None:
        start = 0
    else:
        start = int(float(arg0))
        if start < 0: start = max(0, n + start)
        else: start = min(start, n)
    if arg1 is None:
        end = n
    else:
        end = int(float(arg1))
        if end < 0: end = max(0, n + end)
        else: end = min(end, n)
    return s[start:end]

def js_string_substring(s, arg0, arg1):
    """substring() clamps negatives to 0 and swaps if start > end."""
    n = len(s)
    start = max(0, int(float(arg0))) if arg0 is not None else 0
    end   = max(0, int(float(arg1))) if arg1 is not None else n
    start, end = min(start, n), min(end, n)
    if start > end: start, end = end, start
    return s[start:end]

# FIX 4: JavaScript-accurate array splice
def js_array_splice(arr, args):
    if not args: return []
    n = len(arr)
    # Start
    s = int(float(args[0]))
    if s < 0: s = max(0, n + s)
    else: s = min(s, n)
    # Delete count
    if len(args) < 2:
        del_c = n - s
    else:
        del_c = max(0, min(int(float(args[1])), n - s))
    removed = arr[s:s + del_c]
    arr[s:s + del_c] = args[2:]
    return removed

# ─── 4. THE EVALUATOR ────────────────────────────────────────────────────────

def evaluate(node, env):
    if not isinstance(node, dict): return None
    node_type = node.get("type")

    # STRUCTURES & FLOW
    if node_type in ("Program", "BlockStatement"):
        res = None
        for stmt in node.get("body", []): res = evaluate(stmt, env)
        return res
    elif node_type == "EmptyStatement": return None
    elif node_type == "ExpressionStatement": return evaluate(node.get("expression"), env)
    elif node_type == "ReturnStatement": raise ReturnException(evaluate(node.get("argument"), env))
    elif node_type == "BreakStatement": raise BreakException()
    elif node_type == "ContinueStatement": raise ContinueException()

    # VALUES & VARIABLES
    elif node_type == "Literal": return node.get("value")
    elif node_type == "Identifier":
        name = node.get("name")
        if name in ("undefined", "null"): return None
        if name == "NaN": return math.nan
        if name == "Infinity": return math.inf
        return env.get_var(name)
    elif node_type == "VariableDeclaration":
        for decl in node.get("declarations", []):
            env.set_var(decl.get("id").get("name"), evaluate(decl.get("init"), env))
        return None

    # ARRAYS, OBJECTS & INDEXING
    elif node_type == "ArrayExpression":
        res = []
        for el in node.get("elements", []):
            ev = evaluate(el, env)
            if isinstance(ev, dict) and ev.get("__is_spread"): res.extend(ev["val"])
            else: res.append(ev)
        return res

    elif node_type == "ObjectExpression":
        obj = {}
        for prop in node.get("properties", []):
            k_node = prop.get("key")
            k = k_node.get("name") if k_node.get("type") == "Identifier" else k_node.get("value")
            obj[k] = evaluate(prop.get("value"), env)
        return obj

    elif node_type == "MemberExpression":
        obj = evaluate(node.get("object"), env)
        prop = evaluate(node.get("property"), env) if node.get("computed") else node.get("property").get("name")
        if isinstance(obj, (list, str)) and prop == "length": return len(obj)
        try:
            if isinstance(obj, (list, str)) and str(prop).lstrip('-').isdigit(): return obj[int(prop)]
            if isinstance(obj, dict): return obj.get(prop)
        except: pass
        return None

    # ASSIGNMENTS
    elif node_type == "AssignmentExpression":
        left = node.get("left")
        op = node.get("operator")
        r_val = evaluate(node.get("right"), env)
        if left.get("type") == "Identifier":
            v_name = left.get("name")
            if op == "=": env.set_var(v_name, r_val)
            else: env.set_var(v_name, safe_math(op[0], env.get_var(v_name), r_val))
            return env.get_var(v_name)
        elif left.get("type") == "MemberExpression":
            obj = evaluate(left.get("object"), env)
            prop = evaluate(left.get("property"), env) if left.get("computed") else left.get("property").get("name")
            if isinstance(obj, (list, dict)):
                idx = int(prop) if isinstance(obj, list) else prop
                if op == "=": obj[idx] = r_val
                else: obj[idx] = safe_math(op[0], obj.get(idx, 0), r_val)
                return obj[idx]

    elif node_type == "UpdateExpression":
        arg = node.get("argument")
        op  = node.get("operator")
        if arg.get("type") == "Identifier":
            var_name = arg.get("name")
            cur = env.get_var(var_name)
            cur_val = float(cur) if cur is not None else 0
            new_val = cur_val + 1 if op == "++" else cur_val - 1
            env.set_var(var_name, new_val)
            return new_val if node.get("prefix") else cur_val
        elif arg.get("type") == "MemberExpression":
            obj  = evaluate(arg.get("object"), env)
            prop = evaluate(arg.get("property"), env) if arg.get("computed") else arg.get("property").get("name")
            if isinstance(obj, (list, dict)):
                idx = int(prop) if isinstance(obj, list) else prop
                cur_val = float(obj[idx]) if (isinstance(obj, list) and idx < len(obj)) or (isinstance(obj, dict) and idx in obj) else 0
                new_val = cur_val + 1 if op == "++" else cur_val - 1
                obj[idx] = new_val
                return new_val if node.get("prefix") else cur_val

    # MATH, LOGIC & TERNARY
    elif node_type == "UnaryExpression":
        op  = node.get("operator")
        arg = evaluate(node.get("argument"), env)
        if op == "!": return not arg
        if op == "-":
            try: return -float(arg)
            except: return math.nan
        if op == "typeof":
            if arg is None: return "undefined"
            if isinstance(arg, bool): return "boolean"
            if isinstance(arg, (int, float)): return "number"
            if isinstance(arg, str): return "string"
            return "object"
        if op == "void": return None

    elif node_type == "LogicalExpression":
        l  = evaluate(node.get("left"), env)
        op = node.get("operator")
        if op == "&&": return l if not l else evaluate(node.get("right"), env)
        if op == "||": return l if l else evaluate(node.get("right"), env)
        if op == "??": return evaluate(node.get("right"), env) if l is None else l

    elif node_type == "ConditionalExpression":
        return evaluate(node.get("consequent"), env) if evaluate(node.get("test"), env) else evaluate(node.get("alternate"), env)

    elif node_type == "BinaryExpression":
        l  = evaluate(node.get("left"), env)
        r  = evaluate(node.get("right"), env)
        op = node.get("operator")
        if op in ("+", "-", "*", "/", "%"): return safe_math(op, l, r)
        if op == "**": return float(l) ** float(r)
        if op == "in": return l in r if isinstance(r, (list, dict, str)) else False
        if op == "instanceof": return False  # basic stub
        if op == "===": return type(l) == type(r) and l == r
        if op == "!==": return not (type(l) == type(r) and l == r)
        if op == "==":
            if l is None and r is None: return True
            if l is None or r is None: return False
            return str(l).lower() == str(r).lower() if type(l) != type(r) else l == r
        if op == "!=":
            if l is None and r is None: return False
            if l is None or r is None: return True
            return str(l).lower() != str(r).lower() if type(l) != type(r) else l != r
        try:
            if op == ">":  return float(l) > float(r)
            if op == "<":  return float(l) < float(r)
            if op == ">=": return float(l) >= float(r)
            if op == "<=": return float(l) <= float(r)
        except: return False

    # CONDITIONALS, LOOPS & SWITCH
    elif node_type == "IfStatement":
        if evaluate(node.get("test"), env): return evaluate(node.get("consequent"), env)
        elif node.get("alternate"): return evaluate(node.get("alternate"), env)

    elif node_type == "SwitchStatement":
        disc    = evaluate(node.get("discriminant"), env)
        matched = False
        for case in node.get("cases", []):
            if not matched and case.get("test"):
                if evaluate(case.get("test"), env) == disc: matched = True
            elif not case.get("test"): matched = True
            if matched:
                try:
                    for stmt in case.get("consequent", []): evaluate(stmt, env)
                except BreakException: break
        return None

    elif node_type == "ForStatement":
        loop_env = Environment(parent=env)
        if node.get("init"): evaluate(node.get("init"), loop_env)
        while not node.get("test") or evaluate(node.get("test"), loop_env):
            _check_timeout()  # FIX 5
            try: evaluate(node.get("body"), loop_env)
            except BreakException: break
            except ContinueException: pass
            if node.get("update"): evaluate(node.get("update"), loop_env)

    elif node_type == "ForInStatement":
        obj = evaluate(node.get("right"), env)
        var_node = node.get("left")
        for key in (obj.keys() if isinstance(obj, dict) else range(len(obj)) if isinstance(obj, list) else []):
            _check_timeout()  # FIX 5
            if var_node.get("type") == "VariableDeclaration":
                env.set_var(var_node.get("declarations")[0].get("id").get("name"), str(key))
            else:
                env.set_var(var_node.get("name"), str(key))
            try: evaluate(node.get("body"), env)
            except BreakException: break
            except ContinueException: pass

    elif node_type == "ForOfStatement":
        iterable = evaluate(node.get("right"), env)
        var_node  = node.get("left")
        for item in (iterable if isinstance(iterable, (list, str)) else []):
            _check_timeout()  # FIX 5
            if var_node.get("type") == "VariableDeclaration":
                env.set_var(var_node.get("declarations")[0].get("id").get("name"), item)
            else:
                env.set_var(var_node.get("name"), item)
            try: evaluate(node.get("body"), env)
            except BreakException: break
            except ContinueException: pass

    elif node_type == "WhileStatement":
        while evaluate(node.get("test"), env):
            _check_timeout()  # FIX 5
            try: evaluate(node.get("body"), env)
            except BreakException: break
            except ContinueException: pass

    elif node_type == "DoWhileStatement":
        while True:
            _check_timeout()  # FIX 5
            try: evaluate(node.get("body"), env)
            except BreakException: break
            except ContinueException: pass
            if not evaluate(node.get("test"), env): break

    elif node_type == "TryStatement":
        try:
            evaluate(node.get("block"), env)
        except (ReturnException, BreakException, ContinueException, TimeoutException, RecursionError):
            raise  # always propagate control flow / fatal engine signals
        except Exception as e:
            handler = node.get("handler")
            if handler:
                catch_env = Environment(parent=env)
                param = handler.get("param")
                if param: catch_env.set_var(param.get("name"), str(e))
                evaluate(handler.get("body"), catch_env)
        finally:
            finalizer = node.get("finalizer")
            if finalizer: evaluate(finalizer, env)

    elif node_type == "ThrowStatement":
        raise Exception(js_str(evaluate(node.get("argument"), env)))

    # FUNCTIONS
    elif node_type in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
        if node.get("id"): env.set_var(node.get("id").get("name"), node)

        # FIX 8 (Vuln 3): Arrow functions capture the lexically-enclosing
        # `this` at the moment the function literal is *created* (here),
        # not at call time. We return a shallow copy so that each distinct
        # creation (e.g. a fresh instance built inside a constructor) gets
        # its own captured `this`, without mutating the shared AST node.
        if node.get("_is_arrow"):
            closure = dict(node)
            closure["_captured_this"] = env.get_var("this")
            return closure

        return node

    elif node_type == "NewExpression":
        callee_name = node.get("callee", {}).get("name", "")
        args = [evaluate(a, env) for a in node.get("arguments", [])]
        if callee_name == "Date": return datetime.datetime.now().isoformat()
        if callee_name == "Array":
            if len(args) == 1 and isinstance(args[0], (int, float)):
                return [None] * int(args[0])
            return list(args)
        # User-defined constructor
        func_node = env.get_var(callee_name)
        if func_node:
            instance = {}
            call_js_func(func_node, args, env, this_val=instance)
            return instance
        return None

    elif node_type == "SequenceExpression":
        result = None
        for expr in node.get("expressions", []):
            result = evaluate(expr, env)
        return result

    # ─── CALL EXPRESSION ─────────────────────────────────────────────────────
    elif node_type == "CallExpression":
        callee = node.get("callee")

        # Build args list, expanding spread
        args = []
        for a in node.get("arguments", []):
            ev = evaluate(a, env)
            if isinstance(ev, dict) and ev.get("__is_spread"): args.extend(ev["val"])
            else: args.append(ev)

        if callee.get("type") == "MemberExpression":
            obj_node = callee.get("object")
            prop     = callee.get("property").get("name") if not callee.get("computed") else evaluate(callee.get("property"), env)

            # ── Global objects: console, Math, JSON, Array, Object ────────────
            if obj_node.get("type") == "Identifier":
                obj_name = obj_node.get("name")

                if obj_name == "console":
                    if prop == "log":   print(" ".join(js_str(a) for a in args))
                    if prop == "error": print("Error:", " ".join(js_str(a) for a in args))
                    if prop == "warn":  print("Warn:", " ".join(js_str(a) for a in args))
                    return None

                if obj_name == "Math":
                    a0 = args[0] if args else 0
                    if prop == "floor":   return math.floor(float(a0))
                    if prop == "ceil":    return math.ceil(float(a0))
                    if prop == "round":   return round(float(a0))
                    if prop == "abs":     return abs(float(a0))
                    if prop == "sqrt":    return math.sqrt(float(a0))
                    if prop == "log":     return math.log(float(a0))
                    if prop == "log2":    return math.log2(float(a0))
                    if prop == "log10":   return math.log10(float(a0))
                    if prop == "sin":     return math.sin(float(a0))
                    if prop == "cos":     return math.cos(float(a0))
                    if prop == "tan":     return math.tan(float(a0))
                    if prop == "pow":     return float(a0) ** float(args[1] if len(args) > 1 else 1)
                    if prop == "random":  return random.random()
                    if prop == "max":     return max(float(x) for x in args) if args else -math.inf
                    if prop == "min":     return min(float(x) for x in args) if args else math.inf
                    if prop == "trunc":   return math.trunc(float(a0))
                    if prop == "sign":    return (1 if float(a0) > 0 else -1 if float(a0) < 0 else 0)
                    if prop == "hypot":   return math.hypot(*[float(x) for x in args])
                    return None

                if obj_name == "JSON":
                    if prop == "stringify":
                        import json
                        try: return json.dumps(args[0], separators=(',', ':'))
                        except: return "undefined"
                    if prop == "parse":
                        import json
                        try: return json.loads(args[0])
                        except: return None

                if obj_name == "Array":
                    if prop == "isArray": return isinstance(args[0], list) if args else False
                    if prop == "from":
                        src = args[0]
                        if isinstance(src, (list, str)): return list(src)
                        return []

                if obj_name == "Object":
                    tgt = args[0] if args else {}
                    if prop == "keys":    return list(tgt.keys()) if isinstance(tgt, dict) else []
                    if prop == "values":  return list(tgt.values()) if isinstance(tgt, dict) else []
                    if prop == "entries": return [[k, v] for k, v in tgt.items()] if isinstance(tgt, dict) else []
                    if prop == "assign":
                        for src in args[1:]:
                            if isinstance(src, dict): tgt.update(src)
                        return tgt
                    if prop == "freeze": return tgt  # no-op (we don't enforce immutability)

            # ── Instance methods ──────────────────────────────────────────────
            eval_obj = evaluate(obj_node, env)
            arg0 = args[0] if args else None
            arg1 = args[1] if len(args) > 1 else None

            # STRING METHODS
            if isinstance(eval_obj, str):
                if prop == "split":
                    if arg0 in ("", None): return list(eval_obj)
                    return eval_obj.split(js_str(arg0))
                if prop == "replace":     return eval_obj.replace(js_str(arg0), js_str(arg1), 1)
                if prop == "replaceAll":  return eval_obj.replace(js_str(arg0), js_str(arg1))
                if prop == "slice":       return js_string_slice(eval_obj, arg0, arg1)
                if prop == "substring":   return js_string_substring(eval_obj, arg0, arg1)
                if prop == "trim":        return eval_obj.strip()
                if prop == "trimStart":   return eval_obj.lstrip()
                if prop == "trimEnd":     return eval_obj.rstrip()
                if prop == "toLowerCase": return eval_obj.lower()
                if prop == "toUpperCase": return eval_obj.upper()
                if prop == "includes":    return js_str(arg0) in eval_obj
                if prop == "indexOf":     return eval_obj.find(js_str(arg0))
                if prop == "lastIndexOf": return eval_obj.rfind(js_str(arg0))
                if prop == "startsWith":  return eval_obj.startswith(js_str(arg0))
                if prop == "endsWith":    return eval_obj.endswith(js_str(arg0))
                if prop == "repeat":      return eval_obj * (int(float(arg0)) if arg0 else 0)
                if prop == "padStart":
                    w = int(float(arg0)) if arg0 else 0
                    f = js_str(arg1) if arg1 is not None else " "
                    return eval_obj.rjust(w, f[0] if f else " ")
                if prop == "padEnd":
                    w = int(float(arg0)) if arg0 else 0
                    f = js_str(arg1) if arg1 is not None else " "
                    return eval_obj.ljust(w, f[0] if f else " ")
                if prop == "charAt":      return eval_obj[int(float(arg0))] if arg0 is not None and 0 <= int(float(arg0)) < len(eval_obj) else ""
                if prop == "charCodeAt":  return ord(eval_obj[int(float(arg0))]) if arg0 is not None and 0 <= int(float(arg0)) < len(eval_obj) else math.nan
                if prop == "at":
                    idx = int(float(arg0)) if arg0 is not None else 0
                    if idx < 0: idx = len(eval_obj) + idx
                    return eval_obj[idx] if 0 <= idx < len(eval_obj) else None
                return None

            # ARRAY METHODS
            if isinstance(eval_obj, list):
                if prop == "reverse":  eval_obj.reverse(); return eval_obj
                if prop == "join":     return (js_str(arg0) if args else ",").join(js_str(x) for x in eval_obj)
                if prop == "push":     eval_obj.extend(args); return len(eval_obj)
                if prop == "pop":      return eval_obj.pop() if eval_obj else None
                if prop == "shift":    return eval_obj.pop(0) if eval_obj else None
                if prop == "unshift":
                    for a in reversed(args): eval_obj.insert(0, a)
                    return len(eval_obj)
                if prop == "slice":    return js_array_slice(eval_obj, arg0, arg1)         # FIX 4
                if prop == "splice":   return js_array_splice(eval_obj, args)               # FIX 4
                if prop == "concat":
                    result = list(eval_obj)
                    for a in args: result.extend(a) if isinstance(a, list) else result.append(a)
                    return result
                if prop == "includes": return arg0 in eval_obj
                if prop == "indexOf":  return eval_obj.index(arg0) if arg0 in eval_obj else -1
                if prop == "lastIndexOf":
                    for i in range(len(eval_obj) - 1, -1, -1):
                        if eval_obj[i] == arg0: return i
                    return -1
                if prop == "flat":
                    depth = int(float(arg0)) if arg0 is not None else 1
                    def _flat(lst, d):
                        out = []
                        for item in lst:
                            if isinstance(item, list) and d > 0: out.extend(_flat(item, d - 1))
                            else: out.append(item)
                        return out
                    return _flat(eval_obj, depth)
                if prop == "flatMap":
                    cb = arg0
                    result = []
                    for i, x in enumerate(eval_obj):
                        r = call_js_func(cb, [x, i, eval_obj], env)
                        result.extend(r) if isinstance(r, list) else result.append(r)
                    return result
                if prop == "sort":
                    cb = arg0
                    if cb and isinstance(cb, dict):
                        import functools
                        def cmp(a, b):
                            r = call_js_func(cb, [a, b], env)
                            try: return int(float(r))
                            except: return 0
                        eval_obj.sort(key=functools.cmp_to_key(cmp))
                    else:
                        eval_obj.sort(key=lambda x: js_str(x))
                    return eval_obj
                if prop == "fill":
                    val = arg0
                    s   = int(float(arg1)) if arg1 is not None else 0
                    e   = int(float(args[2])) if len(args) > 2 else len(eval_obj)
                    if s < 0: s = max(0, len(eval_obj) + s)
                    if e < 0: e = max(0, len(eval_obj) + e)
                    for i in range(s, min(e, len(eval_obj))): eval_obj[i] = val
                    return eval_obj
                if prop == "at":
                    idx = int(float(arg0)) if arg0 is not None else 0
                    if idx < 0: idx = len(eval_obj) + idx
                    return eval_obj[idx] if 0 <= idx < len(eval_obj) else None
                if prop == "keys":   return list(range(len(eval_obj)))
                if prop == "values": return list(eval_obj)
                if prop == "entries": return [[i, v] for i, v in enumerate(eval_obj)]

                # CALLBACKS
                if prop in ("map", "filter", "reduce", "reduceRight", "find", "findIndex", "some", "every", "forEach"):
                    cb = arg0
                    if prop == "forEach":
                        for i, x in enumerate(eval_obj): call_js_func(cb, [x, i, eval_obj], env)
                        return None
                    if prop == "map":
                        return [call_js_func(cb, [x, i, eval_obj], env) for i, x in enumerate(eval_obj)]
                    if prop == "filter":
                        return [x for i, x in enumerate(eval_obj) if call_js_func(cb, [x, i, eval_obj], env)]
                    if prop == "some":
                        return any(call_js_func(cb, [x, i, eval_obj], env) for i, x in enumerate(eval_obj))
                    if prop == "every":
                        return all(call_js_func(cb, [x, i, eval_obj], env) for i, x in enumerate(eval_obj))
                    if prop == "find":
                        for i, x in enumerate(eval_obj):
                            if call_js_func(cb, [x, i, eval_obj], env): return x
                        return None
                    if prop == "findIndex":
                        for i, x in enumerate(eval_obj):
                            if call_js_func(cb, [x, i, eval_obj], env): return i
                        return -1
                    if prop == "reduce":
                        acc   = arg1 if len(args) > 1 else eval_obj[0]
                        start = 0 if len(args) > 1 else 1
                        for i in range(start, len(eval_obj)):
                            acc = call_js_func(cb, [acc, eval_obj[i], i, eval_obj], env)
                        return acc
                    if prop == "reduceRight":
                        lst   = list(eval_obj)
                        acc   = arg1 if len(args) > 1 else lst[-1]
                        start = len(lst) - 1 if len(args) > 1 else len(lst) - 2
                        for i in range(start, -1, -1):
                            acc = call_js_func(cb, [acc, lst[i], i, lst], env)
                        return acc

            # OBJECT METHODS on plain dicts
            if isinstance(eval_obj, dict):
                func_val = eval_obj.get(prop)
                if callable(func_val):
                    return func_val(*args)
                if isinstance(func_val, dict) and "body" in func_val:
                    # FIX 3: pass the dict as `this`
                    return call_js_func(func_val, args, env, this_val=eval_obj)
                # hasOwnProperty stub
                if prop == "hasOwnProperty": return arg0 in eval_obj if arg0 else False

            return None

        # ── Identifier-style calls ────────────────────────────────────────────
        elif callee.get("type") == "Identifier":
            func_name = callee.get("name")

            if func_name == "__spread_arg": return {"__is_spread": True, "val": list(args[0]) if args else []}
            if func_name == "parseInt":
                base = int(float(args[1])) if len(args) > 1 and args[1] else 10
                try:
                    s = str(args[0]).strip() if args else ""
                    return int(s, base)
                except: return math.nan
            if func_name == "parseFloat":
                try: return float(str(args[0]).strip()) if args else math.nan
                except: return math.nan
            if func_name == "isNaN":      return math.isnan(float(args[0])) if args else True
            if func_name == "isFinite":   return math.isfinite(float(args[0])) if args else False
            if func_name == "Number":
                if not args: return 0
                try: return float(args[0]) if '.' in str(args[0]) else int(args[0])
                except: return math.nan
            if func_name == "String":     return js_str(args[0]) if args else ""
            if func_name == "Boolean":    return bool(args[0]) if args else False
            if func_name == "Array":      return list(args)

            func_node = env.get_var(func_name)
            return call_js_func(func_node, args, env)

        # ── Callee is itself a call (IIFE / chained) ──────────────────────────
        elif callee.get("type") in ("FunctionExpression", "ArrowFunctionExpression"):
            func_node = evaluate(callee, env)
            return call_js_func(func_node, args, env)

        else:
            func_val = evaluate(callee, env)
            if func_val and isinstance(func_val, dict) and "body" in func_val:
                return call_js_func(func_val, args, env)

    return None


# ─── 5. SMART TRANSPILER (FIX 2, FIX 6, FIX 8) ────────────────────────────────

def _convert_template_literals(code):
    """
    Convert template literals `Hello ${expr}` → "Hello " + (expr) + "".
    Handles nested ${} via brace counting.
    """
    result = []
    i = 0
    while i < len(code):
        if code[i] == '`':
            # Find the matching closing backtick, respecting ${...}
            i += 1
            parts = []
            buf   = []
            while i < len(code) and code[i] != '`':
                if code[i] == '$' and i + 1 < len(code) and code[i + 1] == '{':
                    # flush string buffer
                    if buf: parts.append('"' + ''.join(buf) + '"')
                    buf = []
                    i += 2  # skip ${
                    depth  = 1
                    expr   = []
                    while i < len(code) and depth > 0:
                        if code[i] == '{': depth += 1
                        elif code[i] == '}': depth -= 1
                        if depth > 0: expr.append(code[i])
                        i += 1
                    parts.append('(' + ''.join(expr) + ')')
                else:
                    # escape chars
                    if code[i] == '\n': buf.append('\\n')
                    elif code[i] == '\r': buf.append('\\r')
                    elif code[i] == '"': buf.append('\\"')
                    elif code[i] == '\\' and i + 1 < len(code):
                        buf.append('\\' + code[i + 1]); i += 2; continue
                    else: buf.append(code[i])
                    i += 1
            if code[i:i+1] == '`': i += 1  # consume closing backtick
            if buf: parts.append('"' + ''.join(buf) + '"')
            if not parts: parts = ['""']
            result.append(' + '.join(parts) if len(parts) > 1 else parts[0])
        else:
            result.append(code[i])
            i += 1
    return ''.join(result)


# FIX 6 (Vuln 1): String Masking ───────────────────────────────────────────
#
# The regex-based transpilation passes below (arrow functions, **, ...,
# optional chaining) operate on raw source text. Without protection, a
# perfectly innocent string literal like `"x => x + 1"` or `"...rest"` or
# `"2 ** 8 = 256"` would get its CONTENTS rewritten by those regexes,
# silently corrupting string data.
#
# The fix: before running any of those regexes, sweep the code for every
# double-quoted, single-quoted, and (any leftover) template-literal string,
# stash its *exact* original text, and replace it with an opaque
# `__STR_<n>__` placeholder that none of the transpilation regexes will
# touch. After transpilation, the placeholders are swapped back for the
# original string text verbatim.

_STRING_LITERAL_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"'      # double-quoted strings
    r"|'(?:[^'\\]|\\.)*'"     # single-quoted strings
    r'|`(?:[^`\\]|\\.)*`'     # any leftover template literals (defensive)
)

def _mask_strings(code):
    """Replace string-literal contents with placeholders. Returns
    (masked_code, table) where table[i] is the original literal text
    (including its quote characters) for placeholder __STR_i__."""
    table = []

    def _stash(m):
        table.append(m.group(0))
        return "__STR_%d__" % (len(table) - 1)

    masked = _STRING_LITERAL_RE.sub(_stash, code)
    return masked, table


def _unmask_strings(code, table):
    """Restore placeholders produced by _mask_strings back to the original,
    untouched string literal text."""
    def _restore(m):
        return table[int(m.group(1))]
    return re.sub(r'__STR_(\d+)__', _restore, code)


def _convert_arrow_functions(code):
    """
    Convert arrow functions to ES5 function expressions.

    FIX 8 (Vuln 3): every converted arrow is given the synthetic name
    `__ARROW__` (e.g. `x => x + 1` becomes
    `function __ARROW__(x) { return x + 1; }`). After parsing, the AST
    walker `_tag_arrow_functions` recognises this marker, flags the node
    with `_is_arrow = True`, and strips the synthetic name so it never
    leaks into the variable namespace. `call_js_func` and the evaluator
    then use that flag to give the function lexical (not dynamic) `this`
    semantics.

    Strategy: tokenise so we never corrupt strings or comments, then
    do several targeted passes over the bare-code portions. (String
    contents are additionally protected upstream by _mask_strings.)
    """

    # Pass 1: (a, b, c) => { ... }
    code = re.sub(
        r'\(([^)]*?)\)\s*=>\s*\{',
        lambda m: 'function __ARROW__(' + m.group(1) + ') {',
        code
    )

    # Pass 2: (a, b) => expr   (no braces — expression body)
    def _expr_arrow(m):
        params = m.group(1)
        expr   = m.group(2).rstrip()
        return 'function __ARROW__(' + params + ') { return ' + expr + '; }'

    # loop because of nested: x => y => x + y
    for _ in range(6):
        prev = code
        code = re.sub(
            r'\(([^)]*?)\)\s*=>\s*(?!\{)([^\n,;\])}]+)',
            _expr_arrow,
            code
        )
        # single-param, no parens: x => {...}
        code = re.sub(
            r'(?<![=!<>])\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=>\s*\{',
            r'function __ARROW__(\1) {',
            code
        )
        # single-param, no parens: x => expr
        code = re.sub(
            r'(?<![=!<>])\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=>\s*(?!\{)([^\n,;\])}]+)',
            lambda m: 'function __ARROW__(' + m.group(1) + ') { return ' + m.group(2).rstrip() + '; }',
            code
        )
        if code == prev: break

    return code


def _tag_arrow_functions(node):
    """
    FIX 8 (Vuln 3): Recursively walk the parsed AST and mark every arrow
    function with `_is_arrow = True` so `call_js_func` / `evaluate` can
    give it lexical-`this` semantics instead of dynamic `this` binding.

    Two cases are handled:
      - Genuine `ArrowFunctionExpression` nodes (if pyjsparser parsed an
        arrow literal natively, e.g. one our regex pass missed).
      - `FunctionExpression` / `FunctionDeclaration` nodes produced by
        `_convert_arrow_functions`, identifiable by the synthetic
        `__ARROW__` name we injected. That synthetic name is stripped
        (`id` set to None) so it never becomes a real variable binding.
    """
    if isinstance(node, dict):
        if node.get("type") == "ArrowFunctionExpression":
            node["_is_arrow"] = True
        elif node.get("type") in ("FunctionExpression", "FunctionDeclaration"):
            fid = node.get("id")
            if isinstance(fid, dict) and fid.get("name") == "__ARROW__":
                node["_is_arrow"] = True
                node["id"] = None
        for v in node.values():
            _tag_arrow_functions(v)
    elif isinstance(node, list):
        for item in node:
            _tag_arrow_functions(item)
    return node


def process_js_code(code):
    try:
        # FIX 2a: Template literals → string concatenation
        code = _convert_template_literals(code)

        # FIX 6 (Vuln 1): Mask out string-literal contents so the regex
        # transpilation passes below cannot mutate text that merely
        # *looks* like an arrow function, spread, or exponent operator.
        code, _string_table = _mask_strings(code)

        # FIX 2b / FIX 8: Arrow functions → tagged function expressions
        code = _convert_arrow_functions(code)

        # Exponentiation operator → Math.pow
        code = re.sub(
            r'([\w\.\[\]()]+)\s*\*\*\s*([\w\.\[\]()]+)',
            r'Math.pow(\1, \2)',
            code
        )

        # Spread operator → __spread_arg sentinel
        code = re.sub(r'\.\.\.\s*([a-zA-Z_$][a-zA-Z0-9_$]*)', r'__spread_arg(\1)', code)

        # Optional chaining a?.b → a && a.b (basic, non-nested)
        code = re.sub(
            r'([a-zA-Z_$][a-zA-Z0-9_$.]*)\?\.([a-zA-Z_$][a-zA-Z0-9_$]*)',
            r'\1 && \1.\2',
            code
        )

        # Nullish coalescing: JS ?? is not valid ES5 syntax pyjsparser understands,
        # but pyjsparser ≥0.7 does handle it — leave it; evaluator handles LogicalExpression "??"
        # (if your pyjsparser is old and chokes, uncomment the next line)
        # code = re.sub(r'\?\?', r'||', code)

        # FIX 6 (Vuln 1): restore original string-literal contents verbatim
        code = _unmask_strings(code, _string_table)

    except Exception:
        pass
    return code


# ─── 6. RUNNER ────────────────────────────────────────────────────────────────

def run_js(js_code):
    global _START_TIME, _CALL_DEPTH
    _START_TIME = time.time()   # FIX 5: reset timer per execution
    _CALL_DEPTH = 0              # FIX 7: reset recursion-depth guard per execution
    try:
        processed = process_js_code(js_code)
        ast = parse(processed)
        _tag_arrow_functions(ast)   # FIX 8: annotate arrow functions for lexical `this`
        evaluate(ast, Environment())
    except TimeoutException as e:
        print(f"⏱ TimeoutError: {e}")
    except RecursionError:
        # FIX 7 (Vuln 2): final safety net — should rarely trigger now that
        # _MAX_CALL_DEPTH catches runaway recursion first, but guarantees
        # the host process never dies on a raw Python stack overflow.
        print("⏱ TimeoutError: Maximum call stack size exceeded")
    except Exception as e:
        print(f"Engine Runtime Error: {type(e).__name__}: {e}")


# ─── 7. TERMINAL REPL & FILE HANDLER ─────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            with open(sys.argv[1], "r") as f: run_js(f.read())
        except FileNotFoundError:
            print("File not found! Please check the path.")
    else:
        print("🔥 JS Engine — REPL Mode  (type 'exit' to quit)")
        global_env = Environment()
        while True:
            try:
                code = input("js> ")
                if code.strip().lower() in ("exit", "quit"): break
                if not code.strip(): continue
                _START_TIME = time.time()
                _CALL_DEPTH = 0
                ast = parse(process_js_code(code))
                _tag_arrow_functions(ast)
                result = evaluate(ast, global_env)
                if result is not None: print(js_str(result))
            except TimeoutException as e:
                print(f"⏱ TimeoutError: {e}")
            except RecursionError:
                print("⏱ TimeoutError: Maximum call stack size exceeded")
            except Exception:
                pass  # silently skip incomplete / erroneous lines in REPL
