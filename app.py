import sys
import math
import re
import time
from flask import Flask, render_template, request, jsonify
from pyjsparser import parse

# 🚀 YEH HAI WOH LINE JO GUNICORN KO CHAHIYE!
app = Flask(__name__)

# Recursion limit safety
sys.setrecursionlimit(6000)

# Global logs container for capturing console.log outputs during a web request
_OUTPUT_LOGS = []

# --- 1. MEMORY & EXCEPTIONS ---
class Environment:
    def __init__(self, parent=None):
        self.variables = {}
        self.parent = parent
    def set_var(self, name, value): self.variables[name] = value
    def get_var(self, name):
        if name in self.variables: return self.variables[name]
        if self.parent is not None: return self.parent.get_var(name)
        return None

class ReturnException(Exception):
    def __init__(self, value): self.value = value
class BreakException(Exception): pass
class ContinueException(Exception): pass
class TimeoutException(Exception): pass

_START_TIME = None
_TIMEOUT_SECONDS = 5.0
_CALL_DEPTH = 0
_MAX_CALL_DEPTH = 800

def _check_timeout():
    if _START_TIME is not None and (time.time() - _START_TIME) > _TIMEOUT_SECONDS:
        raise TimeoutException("Execution time limit exceeded (5s)")

# --- 2. JS UTILITIES ---
def js_str(val):
    if val is None: return "undefined"
    if isinstance(val, bool): return str(val).lower()
    if isinstance(val, float):
        if math.isnan(val): return "NaN"
        if math.isinf(val): return "Infinity" if val > 0 else "-Infinity"
        if val.is_integer(): return str(int(val))
    if isinstance(val, list): return ",".join(js_str(x) for x in val)
    if isinstance(val, dict): return "[object Object]"
    return str(val)

def safe_math(op, l, r):
    try:
        lf, rf = float(l), float(r)
        if op == "+": return lf + rf
        if op == "-": return lf - rf
        if op == "*": return lf * rf
        if op == "/": return lf / rf if rf != 0 else (math.inf if lf > 0 else -math.inf)
        if op == "%": return lf % rf if rf != 0 else math.nan
    except:
        if op == "+": return js_str(l) + js_str(r)
        return math.nan

def call_js_func(func_node, args_list, env, this_val=None):
    global _CALL_DEPTH
    _check_timeout()
    if not isinstance(func_node, dict) or "body" not in func_node: return None
    _CALL_DEPTH += 1
    if _CALL_DEPTH > _MAX_CALL_DEPTH:
        _CALL_DEPTH -= 1
        raise TimeoutException("Maximum call stack size exceeded")
    
    local_env = Environment(parent=env)
    if func_node.get("_is_arrow"):
        lexical_this = func_node.get("_captured_this")
        if lexical_this is not None: local_env.set_var("this", lexical_this)
    elif this_val is not None: local_env.set_var("this", this_val)

    params = func_node.get("params", [])
    for i, param in enumerate(params):
        if param.get("type") == "RestElement":
            local_env.set_var(param.get("argument", {}).get("name"), args_list[i:])
            break
        local_env.set_var(param.get("name"), args_list[i] if i < len(args_list) else None)
    
    try:
        body = func_node.get("body")
        if isinstance(body, dict) and body.get("type") == "BlockStatement": 
            evaluate(body, local_env)
        elif body: 
            return evaluate(body, local_env)
    except ReturnException as ret: 
        return ret.value
    finally: 
        _CALL_DEPTH -= 1
    return None

# --- 3. EVALUATOR ---
def evaluate(node, env):
    global _OUTPUT_LOGS
    if not isinstance(node, dict): return None
    _check_timeout()
    
    node_type = node.get("type")
    
    if node_type in ("Program", "BlockStatement"):
        res = None
        for stmt in node.get("body", []): 
            res = evaluate(stmt, env)
        return res
        
    elif node_type == "VariableDeclaration":
        for decl in node.get("declarations", []):
            name = decl.get("id", {}).get("name")
            init_val = evaluate(decl.get("init"), env) if decl.get("init") else None
            env.set_var(name, init_val)
        return None
        
    elif node_type == "ExpressionStatement":
        return evaluate(node.get("expression"), env)
        
    elif node_type == "Literal":
        return node.get("value")
        
    elif node_type == "Identifier":
        name = node.get("name")
        if name == "undefined": return None
        return env.get_var(name)
        
    elif node_type == "BinaryExpression":
        left = evaluate(node.get("left"), env)
        right = evaluate(node.get("right"), env)
        op = node.get("operator")
        if op == "==" or op == "===": return left == right
        if op == "!=" or op == "!==": return left != right
        return safe_math(op, left, right)
        
    elif node_type == "AssignmentExpression":
        left_node = node.get("left")
        right_val = evaluate(node.get("right"), env)
        op = node.get("operator")
        
        if left_node.get("type") == "Identifier":
            name = left_node.get("name")
            if op == "=": current = right_val
            else: current = safe_math(op[:-1], env.get_var(name), right_val)
            env.set_var(name, current)
            return current
        return None

    elif node_type == "UpdateExpression":
        argument = node.get("argument")
        if argument.get("type") == "Identifier":
            name = argument.get("name")
            curr = env.get_var(name)
            if curr is None: curr = 0
            op = node.get("operator")
            new_val = curr + 1 if op == "++" else curr - 1
            env.set_var(name, new_val)
            return curr if node.get("prefix") is False else new_val
        return None
        
    elif node_type == "CallExpression":
        callee = node.get("callee")
        args = [evaluate(a, env) for a in node.get("arguments", [])]
        
        # Intercept console.log for Web Output UI
        if callee.get("type") == "MemberExpression":
            obj = evaluate(callee.get("object"), env)
            prop = callee.get("property", {}).get("name")
            if callee.get("object", {}).get("name") == "console" and prop == "log":
                msg = " ".join(js_str(x) for x in args)
                _OUTPUT_LOGS.append(msg)
                return None
                
            # Array Prototypes (map, filter)
            if isinstance(obj, list):
                if prop == "push":
                    obj.extend(args)
                    return len(obj)
                if prop == "pop": return obj.pop() if obj else None
                if prop == "map" and len(args) > 0:
                    func = args[0]
                    return [call_js_func(func, [item, idx, obj], env) for idx, item in enumerate(obj)]
                if prop == "filter" and len(args) > 0:
                    func = args[0]
                    return [item for idx, item in enumerate(obj) if call_js_func(func, [item, idx, obj], env)]
        
        func_obj = evaluate(callee, env)
        if isinstance(func_obj, dict) and "body" in func_obj:
            return call_js_func(func_obj, args, env)
        return None
        
    elif node_type in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
        func_name = node.get("id", {}).get("name") if node.get("id") else None
        node["_is_arrow"] = (node_type == "ArrowFunctionExpression")
        if node["_is_arrow"]:
            node["_captured_this"] = env.get_var("this")
        if func_name:
            env.set_var(func_name, node)
        return node
        
    elif node_type == "ReturnStatement":
        val = evaluate(node.get("argument"), env) if node.get("argument") else None
        raise ReturnException(val)
        
    elif node_type == "IfStatement":
        test = evaluate(node.get("test"), env)
        if test: return evaluate(node.get("consequent"), env)
        elif node.get("alternate"): return evaluate(node.get("alternate"), env)
        return None
        
    elif node_type == "ForStatement":
        if node.get("init"): evaluate(node.get("init"), env)
        while True:
            if node.get("test") and not evaluate(node.get("test"), env): break
            try:
                evaluate(node.get("body"), env)
            except BreakException: break
            except ContinueException: pass
            if node.get("update"): evaluate(node.get("update"), env)
        return None

    elif node_type == "WhileStatement":
        while evaluate(node.get("test"), env):
            try: evaluate(node.get("body"), env)
            except BreakException: break
            except ContinueException: pass
        return None

    elif node_type == "BreakStatement": raise BreakException()
    elif node_type == "ContinueStatement": raise ContinueException()
    return None

# --- 4. PRE-PROCESSING ---
def process_js_code(code):
    try:
        code = re.sub(r'const\s+', 'var ', code)
        code = re.sub(r'let\s+', 'var ', code)
        code = re.sub(r'\(\s*([a-zA-Z0-9_,\s]*)\s*\)\s*=>\s*\{', r'function(\1) {', code)
        code = re.sub(r'\(\s*([a-zA-Z0-9_,\s]*)\s*\)\s*=>\s*([^,;\\]\)\n]+)', r'function(\1) { return \2; }', code)
    except: pass
    return code

# --- 5. FLASK WEB ROUTES ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/execute', methods=['POST'])
def execute_code():
    global _START_TIME, _CALL_DEPTH, _OUTPUT_LOGS
    _OUTPUT_LOGS = [] 
    _START_TIME = time.time()
    _CALL_DEPTH = 0
    
    data = request.get_json() or {}
    js_code = data.get('code', '')
    
    try:
        processed = process_js_code(js_code)
        ast = parse(processed)
        global_env = Environment()
        evaluate(ast, global_env)
        
        output_str = "\n".join(_OUTPUT_LOGS)
        if not output_str:
            output_str = "Code executed successfully with no output logs."
        return jsonify({"output": output_str, "status": "success"})
        
    except TimeoutException as te:
        return jsonify({"output": f"Runtime Error: {str(te)}", "status": "error"})
    except Exception as e:
        return jsonify({"output": f"Engine Runtime Error: Syntax or Parsing Issue -> {e}", "status": "error"})

if __name__ == '__main__':
    app.run(debug=True)
