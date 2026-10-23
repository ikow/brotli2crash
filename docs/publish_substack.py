#!/usr/bin/env python3
"""
Publish brotli2crash article to Substack.

Converts markdown directly to ProseMirror JSON (Substack's editor format).
Requires: pip install substack

Usage:
  python3 docs/publish_substack.py --cookies 'substack.sid=...'
  python3 docs/publish_substack.py --dry-run
  python3 docs/publish_substack.py --publish-draft 221714203 --cookies '...'
"""

import os
import re
import json
import argparse

PUBLICATION_URL = "https://qideng.substack.com/api/v1"
ARTICLE_PATH = os.path.join(os.path.dirname(__file__), "substack_article.md")
TITLE = 'brotli2crash: The Node.js "Critical RCE" That Can\'t Actually Fire'
SUBTITLE = "CVE-2026-111497 deep analysis: From source code audit to structural unreachability proof"
USER_ID = 287139442


def parse_inline(text):
    """Parse inline markdown (bold, italic, code, links) into ProseMirror text nodes."""
    nodes = []
    i = 0
    while i < len(text):
        m = re.match(r'`([^`]+)`', text[i:])
        if m:
            nodes.append({"type": "text", "text": m.group(1), "marks": [{"type": "code"}]})
            i += m.end()
            continue

        m = re.match(r'\*\*\*(.+?)\*\*\*', text[i:])
        if m:
            nodes.append({"type": "text", "text": m.group(1),
                          "marks": [{"type": "strong"}, {"type": "em"}]})
            i += m.end()
            continue

        m = re.match(r'\*\*(.+?)\*\*', text[i:])
        if m:
            bold_nodes = parse_inline(m.group(1))
            for bn in bold_nodes:
                marks = bn.get("marks", [])
                if not any(mk.get("type") == "strong" for mk in marks):
                    marks = [{"type": "strong"}] + marks
                bn["marks"] = marks
            nodes.extend(bold_nodes)
            i += m.end()
            continue

        m = re.match(r'\*([^*]+?)\*', text[i:])
        if m:
            nodes.append({"type": "text", "text": m.group(1), "marks": [{"type": "em"}]})
            i += m.end()
            continue

        m = re.match(r'\[([^\]]+)\]\(([^)]+)\)', text[i:])
        if m:
            nodes.append({
                "type": "text", "text": m.group(1),
                "marks": [{"type": "link", "attrs": {"href": m.group(2)}}]
            })
            i += m.end()
            continue

        m = re.match(r'[^`*\[]+', text[i:])
        if m:
            nodes.append({"type": "text", "text": m.group(0)})
            i += m.end()
            continue

        nodes.append({"type": "text", "text": text[i]})
        i += 1

    merged = []
    for n in nodes:
        if (merged and n.get("type") == "text" and merged[-1].get("type") == "text"
                and not n.get("marks") and not merged[-1].get("marks")):
            merged[-1]["text"] += n["text"]
        else:
            merged.append(n)
    return merged


def md_to_prosemirror(md_text):
    """Convert markdown to ProseMirror JSON nodes."""
    lines = md_text.split('\n')
    nodes = []
    i = 0

    while i < len(lines):
        line = lines[i]

        if not line.strip():
            i += 1
            continue

        # Fenced code block
        if line.strip().startswith('```'):
            lang = line.strip()[3:].strip()
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code_lines.append(lines[i])
                i += 1
            i += 1
            node = {"type": "codeBlock",
                    "content": [{"type": "text", "text": '\n'.join(code_lines)}]}
            if lang:
                node["attrs"] = {"lang": lang}
            nodes.append(node)
            continue

        # Heading
        m = re.match(r'^(#{1,6})\s+(.+)$', line)
        if m:
            nodes.append({
                "type": "heading",
                "attrs": {"level": len(m.group(1))},
                "content": parse_inline(m.group(2))
            })
            i += 1
            continue

        # Horizontal rule
        if re.match(r'^---+\s*$', line):
            nodes.append({"type": "horizontal_rule"})
            i += 1
            continue

        # Table → paragraphs (Substack has no native table support via API)
        if line.strip().startswith('|') and '|' in line.strip()[1:]:
            while i < len(lines) and lines[i].strip().startswith('|'):
                if not re.match(r'^\|[\s\-:|]+\|$', lines[i].strip()):
                    cells = [c.strip() for c in lines[i].strip().strip('|').split('|')]
                    nodes.append({"type": "paragraph",
                                  "content": parse_inline(' | '.join(cells))})
                i += 1
            continue

        # Bullet list
        if re.match(r'^[-*]\s', line):
            items = []
            while i < len(lines) and re.match(r'^[-*]\s', lines[i]):
                items.append({"type": "listItem", "content": [
                    {"type": "paragraph",
                     "content": parse_inline(re.sub(r'^[-*]\s+', '', lines[i]))}
                ]})
                i += 1
            nodes.append({"type": "bullet_list", "content": items})
            continue

        # Ordered list
        if re.match(r'^\d+\.\s', line):
            items = []
            while i < len(lines) and re.match(r'^\d+\.\s', lines[i]):
                items.append({"type": "listItem", "content": [
                    {"type": "paragraph",
                     "content": parse_inline(re.sub(r'^\d+\.\s+', '', lines[i]))}
                ]})
                i += 1
            nodes.append({"type": "ordered_list", "attrs": {"order": 1}, "content": items})
            continue

        # Paragraph
        para_lines = []
        while (i < len(lines) and lines[i].strip()
               and not lines[i].strip().startswith('#')
               and not lines[i].strip().startswith('```')
               and not re.match(r'^---+\s*$', lines[i])
               and not re.match(r'^[-*]\s', lines[i])
               and not re.match(r'^\d+\.\s', lines[i])
               and not (lines[i].strip().startswith('|') and '|' in lines[i].strip()[1:])):
            para_lines.append(lines[i])
            i += 1

        if para_lines:
            content = parse_inline(' '.join(para_lines))
            if content:
                nodes.append({"type": "paragraph", "content": content})

    return nodes


def build_article(md_text):
    """Build ProseMirror document from article markdown."""
    md_text = re.sub(r'^# .*\n', '', md_text, count=1)
    md_text = re.sub(r'^\*From source code.*\*\s*\n', '', md_text, count=1)
    md_text = re.sub(r'^---\s*$', '', md_text, flags=re.MULTILINE, count=1)
    md_text = md_text.strip()

    parts = md_text.split('<!-- PAYWALL BREAK', 1)
    free_md = parts[0].strip()
    paid_md = parts[1].split('-->', 1)[1].strip() if len(parts) > 1 else ''

    all_nodes = md_to_prosemirror(free_md) + [{"type": "paywall"}] + md_to_prosemirror(paid_md)
    return {"type": "doc", "content": all_nodes}


def main():
    parser = argparse.ArgumentParser(description="Publish brotli2crash to Substack")
    parser.add_argument("--cookies", help="Substack cookies (substack.sid=...)")
    parser.add_argument("--dry-run", action="store_true", help="Show stats without publishing")
    parser.add_argument("--draft-only", action="store_true", help="Create draft, don't publish")
    parser.add_argument("--publish-draft", type=int, help="Publish existing draft by ID")
    args = parser.parse_args()

    cookies = args.cookies or os.environ.get("SUBSTACK_COOKIES")

    if args.publish_draft:
        if not cookies:
            print("Error: need --cookies"); return
        from substack import Api
        api = Api(cookies_string=cookies, publication_url=PUBLICATION_URL)
        print(f"Publishing draft {args.publish_draft}...")
        result = api.publish_draft(args.publish_draft, send=True, share_automatically=False)
        print(f"Published: https://qideng.substack.com/p/{result.get('slug', '')}")
        return

    with open(ARTICLE_PATH) as f:
        md_text = f.read()

    doc = build_article(md_text)
    nodes = doc["content"]

    types = {}
    for n in nodes:
        types[n.get('type', '?')] = types.get(n.get('type', '?'), 0) + 1
    print(f"Nodes: {len(nodes)} | Types: {types}")

    if args.dry_run:
        print("\n=== First 20 nodes ===")
        for i, n in enumerate(nodes[:20]):
            ntype = n.get('type')
            text_parts = []
            for c in n.get('content', [])[:3]:
                if c.get('type') == 'text':
                    marks = [m['type'] for m in c.get('marks', [])]
                    t = c['text'][:40]
                    text_parts.append(f"[{','.join(marks)}]{t}" if marks else t)
            tag = ' <<< PAYWALL' if ntype == 'paywall' else ''
            print(f"  {i:3d}. {ntype:20s} {' '.join(text_parts)[:60]}{tag}")
        return

    if not cookies:
        print("Error: need --cookies or SUBSTACK_COOKIES env"); return

    from substack import Api
    api = Api(cookies_string=cookies, publication_url=PUBLICATION_URL)
    print(f"Authenticated (user={api.get_user_id()})")

    draft_data = {
        'draft_title': TITLE,
        'draft_subtitle': SUBTITLE,
        'draft_body': json.dumps(doc),
        'draft_bylines': [{'id': USER_ID, 'is_guest': False}],
        'audience': 'only_paid',
        'type': 'newsletter',
        'section_chosen': True,
    }

    print("Creating draft...")
    result = api.post_draft(draft_data)
    draft_id = result.get('id')
    edit_url = f"https://qideng.substack.com/publish/post/{draft_id}"
    print(f"Draft: {edit_url}")

    if args.draft_only:
        return

    print("Publishing...")
    pub = api.publish_draft(draft_id, send=True, share_automatically=False)
    print(f"Published: https://qideng.substack.com/p/{pub.get('slug', '')}")


if __name__ == "__main__":
    main()
