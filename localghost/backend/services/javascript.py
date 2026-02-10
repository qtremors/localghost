"""Parse JavaScript/TypeScript without running project code."""

import ast

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Parser

UNKNOWN = object()


def parse(text, filename):
    language = tree_sitter_typescript.language_tsx() if filename.endswith(('.tsx', '.jsx')) else tree_sitter_typescript.language_typescript() if filename.endswith(('.ts', '.mts', '.cts')) else tree_sitter_javascript.language()
    return Parser(Language(language)).parse(text.encode('utf-8'))


def walk(node):
    stack = [node]
    while stack:
        item = stack.pop()
        yield item
        stack.extend(reversed(item.named_children))


def text(node):
    return node.text.decode('utf-8', errors='replace') if node else ''


def scalar(node):
    if node is None:
        return UNKNOWN
    if node.type == 'string':
        try:
            return ast.literal_eval(text(node))
        except (ValueError, SyntaxError):
            return UNKNOWN
    if node.type == 'template_string' and not any(child.type == 'template_substitution' for child in node.named_children):
        return text(node)[1:-1]
    if node.type in ('true', 'false', 'null'):
        return {'true': True, 'false': False, 'null': None}[node.type]
    if node.type == 'number':
        try:
            return float(text(node))
        except ValueError:
            return UNKNOWN
    return UNKNOWN


def pairs(node):
    if not node or node.type != 'object':
        return {}
    return {text(item.child_by_field_name('key')).strip('\"\''): item.child_by_field_name('value')
            for item in node.named_children if item.type == 'pair'}


def unwrap(node):
    while node and node.type in ('parenthesized_expression', 'as_expression', 'satisfies_expression'):
        node = node.named_children[0]
    return node


def evaluate(node, mode, bindings, depth=0):
    """Only literal data and known environment conditions are evaluated."""
    node = unwrap(node)
    if node is None or depth > 30:
        return UNKNOWN
    value = scalar(node)
    if value is not UNKNOWN:
        return value
    expression = text(node)
    if node.type == 'identifier':
        if expression == 'mode':
            return mode
        if expression in bindings:
            return evaluate(bindings[expression], mode, bindings, depth + 1)
        return UNKNOWN
    compact = expression.replace(' ', '')
    if compact in ('process.env.NODE_ENV', 'import.meta.env.MODE'):
        return mode
    if compact == 'import.meta.env.PROD':
        return mode == 'production'
    if compact == 'import.meta.env.DEV':
        return mode == 'development'
    if node.type == 'unary_expression' and node.named_children:
        argument = evaluate(node.named_children[-1], mode, bindings, depth + 1)
        return not argument if argument is not UNKNOWN and expression.startswith('!') else UNKNOWN
    if node.type == 'binary_expression':
        left = evaluate(node.child_by_field_name('left'), mode, bindings, depth + 1)
        right = evaluate(node.child_by_field_name('right'), mode, bindings, depth + 1)
        operator = next((text(child) for child in node.children if not child.is_named), '')
        if operator == '&&' and left is not UNKNOWN and not left:
            return left
        if operator in ('||', '??') and left is not UNKNOWN and left:
            return left
        if left is UNKNOWN or right is UNKNOWN:
            return UNKNOWN
        if operator in ('===', '=='):
            return left == right
        if operator in ('!==', '!='):
            return left != right
        if operator == '&&':
            return left and right
        if operator in ('||', '??'):
            return left or right
        if operator == '+' and isinstance(left, str) and isinstance(right, str):
            return left + right
        return UNKNOWN
    if node.type == 'ternary_expression':
        condition = evaluate(node.child_by_field_name('condition'), mode, bindings, depth + 1)
        if condition is UNKNOWN:
            return UNKNOWN
        return evaluate(node.child_by_field_name('consequence' if condition else 'alternative'), mode, bindings, depth + 1)
    if node.type in ('arrow_function', 'function_expression', 'function_declaration'):
        body = node.child_by_field_name('body')
        if body and body.type == 'statement_block':
            returns = [item for item in body.named_children if item.type == 'return_statement']
            body = returns[0].named_children[0] if len(returns) == 1 and returns[0].named_children else None
        return evaluate(body, mode, bindings, depth + 1)
    if node.type == 'call_expression' and text(node.child_by_field_name('function')) in ('defineConfig', 'defineNextConfig'):
        args = node.child_by_field_name('arguments')
        return evaluate(args.named_children[0], mode, bindings, depth + 1) if args and args.named_children else UNKNOWN
    if node.type == 'array':
        values = [evaluate(item, mode, bindings, depth + 1) for item in node.named_children]
        return values if all(value is not UNKNOWN for value in values) else UNKNOWN
    if node.type == 'object':
        result = {}
        for item in node.named_children:
            if item.type == 'pair':
                key = text(item.child_by_field_name('key')).strip('\"\'')
                result[key] = evaluate(item.child_by_field_name('value'), mode, bindings, depth + 1)
            elif item.type == 'spread_element':
                spread = evaluate(item.named_children[0], mode, bindings, depth + 1)
                if isinstance(spread, dict):
                    result.update(spread)
                else:
                    result['[computed spread]'] = UNKNOWN
        return result
    return UNKNOWN


def config_settings(source, filename):
    tree = parse(source, filename)
    bindings = {text(node.child_by_field_name('name')): node.child_by_field_name('value') for node in walk(tree.root_node) if node.type == 'variable_declarator'}
    exports = [node.child_by_field_name('value') for node in tree.root_node.named_children if node.type == 'export_statement' and node.child_by_field_name('value')]
    exports += [node.child_by_field_name('right') for node in walk(tree.root_node) if node.type == 'assignment_expression' and text(node.child_by_field_name('left')).replace(' ', '') in ('module.exports', 'exports.default')]
    if not exports:
        return [], True
    exported = exports[-1]
    values = {mode: evaluate(exported, mode, bindings) for mode in ('development', 'production')}
    locations = {}

    def collect(node, prefix='', depth=0):
        node = unwrap(node)
        if node is None or depth > 30:
            return
        if node.type == 'identifier' and text(node) in bindings:
            collect(bindings[text(node)], prefix, depth + 1)
        elif node.type == 'object':
            for item in node.named_children:
                if item.type == 'pair':
                    key = text(item.child_by_field_name('key')).strip("\"'")
                    path = prefix + '.' + key if prefix else key
                    value = item.child_by_field_name('value')
                    if unwrap(value).type == 'object':
                        collect(value, path, depth + 1)
                    else:
                        locations[path] = (item, value)
                        collect(value, path, depth + 1)
                elif item.type == 'spread_element' and item.named_children:
                    collect(item.named_children[0], prefix, depth + 1)
        elif node.type == 'call_expression' and text(node.child_by_field_name('function')) in ('defineConfig', 'defineNextConfig'):
            args = node.child_by_field_name('arguments')
            if args and args.named_children:
                collect(args.named_children[0], prefix, depth + 1)
        elif node.type in ('arrow_function', 'function_expression', 'function_declaration'):
            collect(node.child_by_field_name('body'), prefix, depth + 1)
        elif node.type == 'statement_block':
            returns = [item for item in node.named_children if item.type == 'return_statement']
            if len(returns) == 1 and returns[0].named_children:
                collect(returns[0].named_children[0], prefix, depth + 1)
        elif node.type == 'ternary_expression':
            collect(node.child_by_field_name('consequence'), prefix, depth + 1)
            collect(node.child_by_field_name('alternative'), prefix, depth + 1)

    def at_path(value, path):
        for part in path.split('.'):
            value = value.get(part, UNKNOWN) if isinstance(value, dict) else UNKNOWN
        return value

    def known(item):
        return all(known(child) for child in item.values()) if isinstance(item, dict) else all(known(child) for child in item) if isinstance(item, list) else item is not UNKNOWN

    collect(exported)
    settings = []
    for key, (node, value_node) in locations.items():
        resolved = {mode: at_path(value, key) for mode, value in values.items()}
        if any(isinstance(value, dict) for value in resolved.values()):
            continue
        settings.append({'key': key, 'line': node.start_point.row + 1,
                         'start': value_node.start_byte, 'end': value_node.end_byte,
                         'patch_safe': all(evaluate(value_node, mode, bindings) == resolved[mode] for mode in resolved),
                         **{mode: value if known(value) else None for mode, value in resolved.items()},
                         'known': {mode: known(value) for mode, value in resolved.items()}})
    return settings, tree.root_node.has_error or not all(isinstance(value, dict) for value in values.values())


def router_paths(source, filename):
    tree = parse(source, filename)
    router_imports = [node for node in walk(tree.root_node) if node.type == 'import_statement' and 'react-router' in text(node.child_by_field_name('source'))]
    if not router_imports:
        return [], []
    aliases = {'Route'}
    factories = {'createBrowserRouter', 'createHashRouter', 'useRoutes'}
    for statement in router_imports:
        for node in walk(statement):
            if node.type == 'import_specifier':
                name = text(node.child_by_field_name('name'))
                alias = text(node.child_by_field_name('alias')) or name
                if name == 'Route':
                    aliases.add(alias)
                elif name in factories:
                    factories.add(alias)
    routes, unresolved = [], []
    bindings = {text(node.child_by_field_name('name')): node.child_by_field_name('value') for node in walk(tree.root_node) if node.type == 'variable_declarator'}

    def resolve(node):
        node = unwrap(node)
        seen = set()
        while node and node.type == 'identifier' and text(node) in bindings and text(node) not in seen:
            seen.add(text(node))
            node = unwrap(bindings[text(node)])
        return node

    def join(parent, value):
        if value.startswith('/'):
            return value
        return (parent.rstrip('/') + '/' + value).replace('//', '/') or '/'

    def add(value, node, hash_router=False):
        if not isinstance(value, str) or len(value) > 2048 or '\\' in value:
            unresolved.append({'file': filename, 'line': node.start_point.row + 1, 'reason': 'Route path is computed at runtime.'})
            return
        path = ('/#' + value) if hash_router else value
        routes.append({'path': path, 'file': filename, 'line': node.start_point.row + 1, 'kind': 'react-router'})

    def route_object(node, parent='/', hash_router=False):
        props = pairs(resolve(node))
        if not props:
            return
        value = scalar(resolve(props.get('path')))
        if 'path' in props and value is UNKNOWN:
            add(UNKNOWN, node, hash_router)
        path = join(parent, value) if isinstance(value, str) else parent
        if value is not UNKNOWN or scalar(props.get('index')) is True:
            add(path, node, hash_router)
        children = resolve(props.get('children'))
        if children and children.type == 'array':
            for child in children.named_children:
                route_object(child, path, hash_router)

    for node in walk(tree.root_node):
        if node.type != 'call_expression':
            continue
        name = text(node.child_by_field_name('function'))
        args = node.child_by_field_name('arguments')
        if name.split('.')[-1] in factories and args and args.named_children:
            first = resolve(args.named_children[0])
            if first.type == 'array':
                for child in first.named_children:
                    route_object(child, hash_router='Hash' in name)
            else:
                unresolved.append({'file': filename, 'line': node.start_point.row + 1, 'reason': 'Router configuration is not a literal array.'})

    def jsx(node, parent='/', hash_router=False):
        if node.type not in ('jsx_element', 'jsx_self_closing_element'):
            return
        opening = node.child_by_field_name('open_tag') if node.type == 'jsx_element' else node
        name = text(opening.child_by_field_name('name')) if opening else ''
        path = parent
        hash_router = hash_router or name.split('.')[-1] == 'HashRouter'
        if name.split('.')[-1] in aliases:
            attributes = {text(item.named_children[0]): item.named_children[1] if len(item.named_children) > 1 else None
                          for item in opening.named_children if item.type == 'jsx_attribute'}
            route = attributes.get('path')
            if route and route.type == 'jsx_expression' and route.named_children:
                route = route.named_children[0]
            value = scalar(resolve(route))
            if isinstance(value, str):
                path = join(parent, value)
                add(path, opening, hash_router)
            elif 'index' in attributes:
                add(parent, opening, hash_router)
            elif route:
                add(UNKNOWN, opening, hash_router)
        for child in node.named_children:
            if child != opening:
                jsx(child, path, hash_router)

    for node in walk(tree.root_node):
        if node.type in ('jsx_element', 'jsx_self_closing_element') and (not node.parent or node.parent.type not in ('jsx_element', 'jsx_expression')):
            jsx(node)
    unique = {item['path']: item for item in routes}
    return list(unique.values()), unresolved
