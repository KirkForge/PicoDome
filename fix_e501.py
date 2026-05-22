#!/usr/bin/env python3
"""Auto-fix E501 line-too-long issues - fast single-pass approach."""
import subprocess
import re
import os

os.chdir("/home/krk/.picoclaw/workspace/IronDome-main")

# Step 1: Get ALL E501 violations in one flake8 call
result = subprocess.run(
    ["python3", "-m", "flake8", "src/", "tests/", "--select=E501"],
    capture_output=True, text=True
)

# Parse into {filepath: {lineno: line_length}}
violations = {}
for line in result.stdout.strip().split('\n'):
    if not line.strip():
        continue
    parts = line.split(':')
    if len(parts) < 3:
        continue
    filepath = parts[0]
    lineno = int(parts[1])
    match = re.search(r'\((\d+) > 79', line)
    if match:
        if filepath not in violations:
            violations[filepath] = {}
        violations[filepath][lineno] = int(match.group(1))

print(f"Found {sum(len(v) for v in violations.values())} E501 violations in {len(violations)} files")

# Step 2: For each file, fix the long lines
def fix_long_line(line, indent):
    """Fix a single long line. Returns list of replacement lines (without newlines)."""
    stripped = line.rstrip('\n').rstrip('\r')
    if len(stripped) <= 79:
        return [stripped]
    
    content = stripped[len(indent):]
    
    # --- IMPORTS ---
    if content.startswith('from ') and ' import ' in content:
        return wrap_import(stripped, indent)
    
    if content.startswith('import '):
        return wrap_bare_import(stripped, indent)
    
    # --- COMMENTS ---
    if content.startswith('#'):
        return wrap_comment(stripped, indent)
    
    # --- INLINE COMMENTS ---
    comment_idx = find_inline_comment(content)
    if comment_idx is not None:
        code_part = content[:comment_idx].rstrip()
        comment_part = content[comment_idx:]
        if len(indent + code_part) <= 79:
            if len(indent + code_part + '  ' + comment_part.lstrip('# ')) <= 79:
                return [indent + code_part + '  ' + comment_part.lstrip('# ')]
            else:
                wrapped_code = [indent + code_part]
                wrapped_comment = wrap_comment(indent + comment_part, indent)
                return wrapped_code + wrapped_comment
        else:
            wrapped_code = fix_long_line(indent + code_part, indent)
            wrapped_comment = wrap_comment(indent + comment_part, indent)
            return wrapped_code + wrapped_comment
    
    # --- PARENTHESIZED EXPRESSIONS ---
    bracket_info = find_open_brackets(content)
    if bracket_info:
        return wrap_in_brackets(stripped, indent, content, bracket_info)
    
    # --- ASSIGNMENTS ---
    assign_match = re.search(r'(?<![=!<>])\s*=\s', content)
    if assign_match and not content.startswith('def ') and not content.startswith('class '):
        return wrap_assignment(stripped, indent, content, assign_match)
    
    # --- FUNCTION/CLASS DEFS ---
    if content.startswith('def ') or content.startswith('class '):
        return wrap_def(stripped, indent, content)
    
    # --- RETURN/YIELD/RAISE/ASSERT ---
    if content.startswith(('return ', 'yield ', 'raise ', 'assert ')):
        return wrap_keyword_expr(stripped, indent, content)
    
    # --- DICT LITERALS / LIST LITERALS ---
    if content.startswith(('{', '[')) and content.endswith(('}', ']')):
        return wrap_collection(stripped, indent, content)
    
    # --- METHOD CHAINS ---
    if '.(' in content:
        return wrap_method_chain(stripped, indent, content)
    
    # --- COMMA-SEPARATED (not in brackets) ---
    if ',' in content:
        return wrap_comma_separated(stripped, indent, content)
    
    # --- BACKSLASH CONTINUATION (last resort) ---
    return wrap_backslash(stripped, indent, content)


def find_inline_comment(content):
    """Find inline # comment position, respecting strings."""
    in_string = False
    string_char = None
    i = 0
    while i < len(content):
        c = content[i]
        if in_string:
            if c == '\\' and i + 1 < len(content):
                i += 2
                continue
            if c == string_char:
                in_string = False
        elif c in ('"', "'"):
            if content[i:i+3] in ('"""', "'''"):
                return None
            string_char = c
            in_string = True
        elif c == '#':
            return i
        i += 1
    return None


def find_open_brackets(content):
    """Find unmatched opening brackets."""
    stack = []
    for i, c in enumerate(content):
        if c in '([{':
            stack.append((i, c))
        elif c in ')]}':
            if stack:
                stack.pop()
    return stack


def wrap_import(line, indent):
    content = line[len(indent):]
    match = re.match(r'from\s+(.+?)\s+import\s+(.+)', content)
    if not match:
        return [line]
    
    module = match.group(1)
    imports_str = match.group(2)
    
    if '(' in imports_str:
        return [line]
    
    imports = [i.strip() for i in imports_str.split(',')]
    
    result = [f'{indent}from {module} import (']
    for imp in imports:
        result.append(f'{indent}    {imp},')
    result.append(f'{indent})')
    return result


def wrap_bare_import(line, indent):
    content = line[len(indent):]
    modules = [m.strip() for m in content[7:].split(',')]
    if len(modules) <= 1:
        return [line[:79] + ' \\']
    result = [f'{indent}import (']
    for m in modules:
        result.append(f'{indent}    {m},')
    result.append(f'{indent})')
    return result


def wrap_comment(line, indent):
    content = line[len(indent):]
    prefix_match = re.match(r'^(#+\s*)', content)
    prefix = prefix_match.group(1) if prefix_match else '# '
    text = content[len(prefix):]
    
    max_text_len = 79 - len(indent) - len(prefix)
    if max_text_len < 20:
        max_text_len = 20
    
    words = text.split()
    result = []
    current = ''
    for word in words:
        test = (current + ' ' + word).strip()
        if len(test) > max_text_len and current:
            result.append(indent + prefix + current)
            current = word
        else:
            current = test
    if current:
        result.append(indent + prefix + current)
    return result if result else [line]


def wrap_in_brackets(line, indent, content, bracket_info):
    """Wrap by breaking after opening bracket."""
    first_pos, first_char = bracket_info[0]
    close_char = {'(': ')', '[': ']', '{': '}'}[first_char]
    
    before = content[:first_pos + 1]
    depth = 0
    close_pos = -1
    for i in range(first_pos, len(content)):
        if content[i] == first_char:
            depth += 1
        elif content[i] == close_char:
            depth -= 1
            if depth == 0:
                close_pos = i
                break
    
    if close_pos == -1:
        return wrap_backslash(line, indent, content)
    
    after_close = content[close_pos + 1:]
    inside = content[first_pos + 1:close_pos]
    
    inner_indent = indent + '    '
    
    first_line = indent + before
    if len(first_line) > 79:
        return wrap_backslash(line, indent, content)
    
    items = split_top_level(inside, ',')
    
    if len(items) <= 1:
        item = items[0].strip() if items else ''
        if item and len(inner_indent + item + after_close) <= 79:
            return [first_line, inner_indent + item + after_close]
        elif not item and len(first_line + after_close) <= 79:
            return [first_line + after_close]
        else:
            return [first_line, inner_indent + item, indent + close_char + after_close]
    
    result = [first_line]
    for item in items:
        item_stripped = item.strip()
        if item_stripped:
            if len(inner_indent + item_stripped + ',') <= 79:
                result.append(inner_indent + item_stripped + ',')
            else:
                sub = fix_long_line(inner_indent + item_stripped, inner_indent)
                if sub:
                    sub[-1] = sub[-1] + ','
                result.extend(sub)
    result.append(indent + close_char + after_close)
    return result


def split_top_level(text, delimiter):
    """Split at delimiter only at top level."""
    items = []
    current = ''
    depth = 0
    in_string = False
    string_char = None
    i = 0
    while i < len(text):
        c = text[i]
        if in_string:
            current += c
            if c == '\\' and i + 1 < len(text):
                i += 1
                current += text[i]
            elif c == string_char:
                in_string = False
        elif c in ('"', "'"):
            if text[i:i+3] in ('"""', "'''"):
                end_quote = text[i:i+3]
                end = text.find(end_quote, i + 3)
                if end >= 0:
                    current += text[i:end+3]
                    i = end + 2
                else:
                    current += text[i:]
                    break
            else:
                string_char = c
                in_string = True
                current += c
        elif c in '([{':
            depth += 1
            current += c
        elif c in ')]}':
            depth -= 1
            current += c
        elif c == delimiter and depth == 0:
            items.append(current)
            current = ''
        else:
            current += c
        i += 1
    if current.strip():
        items.append(current)
    return items


def wrap_assignment(line, indent, content, assign_match):
    """Wrap at = sign."""
    pos = assign_match.start()
    end = assign_match.end()
    while end < len(content) and content[end] == ' ':
        end += 1
    
    lhs = content[:pos].rstrip()
    rhs = content[end:].lstrip() if end < len(content) else ''
    op = '='
    
    first_line = indent + lhs + ' ' + op
    if len(first_line) > 79:
        return wrap_backslash(line, indent, content)
    
    inner_indent = indent + '    '
    
    if rhs and rhs[0] in '([{':
        wrapped_rhs = fix_long_line(inner_indent + rhs, inner_indent)
        return [first_line] + wrapped_rhs
    
    if len(inner_indent + rhs) <= 79:
        return [first_line, inner_indent + rhs]
    
    wrapped_rhs = fix_long_line(inner_indent + rhs, inner_indent)
    return [first_line] + wrapped_rhs


def wrap_def(line, indent, content):
    """Wrap function/class definitions."""
    paren_pos = content.find('(')
    if paren_pos < 0:
        return wrap_backslash(line, indent, content)
    
    before_paren = content[:paren_pos + 1]
    depth = 0
    close_pos = -1
    for i in range(paren_pos, len(content)):
        if content[i] == '(':
            depth += 1
        elif content[i] == ')':
            depth -= 1
            if depth == 0:
                close_pos = i
                break
    
    if close_pos < 0:
        return wrap_backslash(line, indent, content)
    
    after_close = content[close_pos + 1:]
    params = content[paren_pos + 1:close_pos]
    
    first_line = indent + before_paren
    if len(first_line) > 79:
        return wrap_backslash(line, indent, content)
    
    param_items = split_top_level(params, ',')
    inner_indent = indent + '    '
    
    result = [first_line]
    for p in param_items:
        p_stripped = p.strip()
        if p_stripped:
            p_line = inner_indent + p_stripped + ','
            if len(p_line) <= 79:
                result.append(p_line)
            else:
                sub = fix_long_line(inner_indent + p_stripped, inner_indent)
                if sub:
                    sub[-1] = sub[-1] + ','
                result.extend(sub)
    result.append(indent + ')' + after_close)
    return result


def wrap_keyword_expr(line, indent, content):
    """Wrap return/yield/raise/assert."""
    keyword_match = re.match(r'(return|yield|raise|assert)\s+', content)
    if not keyword_match:
        return wrap_backslash(line, indent, content)
    
    keyword = keyword_match.group(1)
    expr = content[keyword_match.end():]
    
    first_line = indent + keyword
    inner_indent = indent + '    '
    
    if len(inner_indent + expr) <= 79:
        return [first_line, inner_indent + expr]
    
    wrapped = fix_long_line(inner_indent + expr, inner_indent)
    return [first_line] + wrapped


def wrap_collection(line, indent, content):
    """Wrap dict/list literals."""
    if content.startswith('{'):
        open_c, close_c = '{', '}'
    else:
        open_c, close_c = '[', ']'
    
    inner = content[1:-1].strip()
    inner_indent = indent + '    '
    
    items = split_top_level(inner, ',')
    
    result = [indent + open_c]
    for item in items:
        s = item.strip()
        if s:
            if len(inner_indent + s + ',') <= 79:
                result.append(inner_indent + s + ',')
            else:
                sub = fix_long_line(inner_indent + s, inner_indent)
                if sub:
                    sub[-1] = sub[-1] + ','
                result.extend(sub)
    result.append(indent + close_c)
    return result


def wrap_method_chain(line, indent, content):
    """Wrap method chains at dots."""
    parts = []
    current = ''
    depth = 0
    for i, c in enumerate(content):
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        if c == '.' and depth == 0 and i > 0 and current:
            parts.append(current)
            current = '.'
        else:
            current += c
    if current:
        parts.append(current)
    
    if len(parts) <= 1:
        return wrap_backslash(line, indent, content)
    
    result = []
    first = indent + parts[0]
    if len(first + parts[1]) <= 79:
        result.append(first + parts[1])
        remaining = parts[2:]
    else:
        result.append(first)
        remaining = parts[1:]
    
    inner_indent = indent + '    '
    for p in remaining:
        p_line = inner_indent + p
        if len(p_line) <= 79:
            result.append(p_line)
        else:
            result.extend(fix_long_line(p_line, inner_indent))
    
    return result


def wrap_comma_separated(line, indent, content):
    """Wrap comma-separated items not in brackets."""
    items = split_top_level(content, ',')
    if len(items) <= 1:
        return wrap_backslash(line, indent, content)
    
    result = []
    current_line = indent
    for i, item in enumerate(items):
        s = item.strip()
        if not s:
            continue
        test = current_line + (', ' if current_line != indent else '') + s
        if len(test) <= 79:
            current_line = test
        else:
            if current_line != indent:
                result.append(current_line + ',')
            current_line = indent + '    ' + s
            if len(current_line) > 79:
                sub = fix_long_line(current_line, indent + '    ')
                result.extend(sub[:-1])
                current_line = sub[-1]
    
    if current_line.strip():
        result.append(current_line)
    
    return result if result else [line]


def wrap_backslash(line, indent, content):
    """Last resort: backslash continuation."""
    max_len = 79 - len(indent)
    if len(content) <= max_len:
        return [indent + content]
    
    best = -1
    for i in range(min(max_len, len(content)) - 1, 0, -1):
        if content[i] == ',' or (content[i] in ' \t' and i + 1 < len(content) and content[i+1] not in ')]},'):
            best = i + 1
            break
    
    if best <= 1:
        best = max_len
        for i in range(best - 1, max_len // 2, -1):
            if content[i] in ' \t':
                best = i + 1
                break
    
    first = content[:best].rstrip()
    rest = content[best:].lstrip()
    
    result = [indent + first + ' \\']
    inner_indent = indent + '    '
    
    if len(inner_indent + rest) <= 79:
        result.append(inner_indent + rest)
    else:
        result.extend(fix_long_line(inner_indent + rest, inner_indent))
    
    return result


# Process each file
total_fixed = 0
for filepath, line_violations in violations.items():
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    new_lines = []
    for i, line in enumerate(lines):
        lineno = i + 1
        if lineno in line_violations:
            indent_match = re.match(r'^(\s*)', line)
            indent = indent_match.group(1) if indent_match else ''
            wrapped = fix_long_line(line, indent)
            new_lines.extend([l + '\n' for l in wrapped])
            total_fixed += 1
        else:
            new_lines.append(line)
    
    with open(filepath, 'w') as f:
        f.writelines(new_lines)

print(f"Fixed {total_fixed} lines in first pass")

# Check remaining
result = subprocess.run(
    ["python3", "-m", "flake8", "src/", "tests/", "--select=E501,E302", "--count", "--statistics"],
    capture_output=True, text=True
)
print(f"After pass 1:\n{result.stdout}")

# Iterative fixing
for pass_num in range(2, 15):
    result = subprocess.run(
        ["python3", "-m", "flake8", "src/", "tests/", "--select=E501"],
        capture_output=True, text=True
    )
    
    if not result.stdout.strip():
        print(f"All E501 fixed after pass {pass_num - 1}!")
        break
    
    violations = {}
    for vline in result.stdout.strip().split('\n'):
        if not vline.strip():
            continue
        parts = vline.split(':')
        if len(parts) < 3:
            continue
        fp = parts[0]
        ln = int(parts[1])
        if fp not in violations:
            violations[fp] = {}
        violations[fp][ln] = True
    
    count = sum(len(v) for v in violations.values())
    print(f"Pass {pass_num}: {count} E501 remaining")
    if count > 200:
        print("Too many remaining, showing sample:")
        for vline in result.stdout.strip().split('\n')[:10]:
            print(f"  {vline}")
    
    for filepath, line_violations in violations.items():
        with open(filepath, 'r') as f:
            lines = f.readlines()
        
        new_lines = []
        for i, line in enumerate(lines):
            lineno = i + 1
            if lineno in line_violations:
                indent_match = re.match(r'^(\s*)', line)
                indent = indent_match.group(1) if indent_match else ''
                wrapped = fix_long_line(line, indent)
                new_lines.extend([l + '\n' for l in wrapped])
            else:
                new_lines.append(line)
        
        with open(filepath, 'w') as f:
            f.writelines(new_lines)
else:
    print("WARNING: Could not fix all E501 issues")

# Fix E302
print("\nFixing E302 issues...")
for fp, ln in [("tests/test_cluster.py", 43), ("tests/test_notary.py", 28)]:
    with open(fp, 'r') as f:
        lines = f.readlines()
    
    idx = ln - 1
    blank_count = 0
    check = idx - 1
    while check >= 0 and lines[check].strip() == '':
        blank_count += 1
        check -= 1
    
    if blank_count < 2:
        insert_at = idx - blank_count
        for _ in range(2 - blank_count):
            lines.insert(insert_at, '\n')
    
    with open(fp, 'w') as f:
        f.writelines(lines)

# Final check
result = subprocess.run(
    ["python3", "-m", "flake8", "src/", "tests/", "--count"],
    capture_output=True, text=True
)
print(f"\nFinal flake8 result:\n{result.stdout}")