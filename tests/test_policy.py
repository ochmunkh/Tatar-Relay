"""Repository policy guard (tools/policy_check.py).

The project rule is that the public tree never carries organisation/product
names, a company name, or AI-tool attribution. The guard stores those tokens as
SHA-256 digests only; these tests use a synthetic digest set so no real name is
needed here either.
"""
import hashlib
import importlib.util
import io
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("policy_check", ROOT / "tools" / "policy_check.py")
policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(policy)

FAKE = {hashlib.sha256(b"zzforbiddenzz").hexdigest()}


def test_tracked_tree_is_clean():
    findings = policy.scan_tree()
    assert not findings, "\n".join(findings)


def test_text_detection_is_case_insensitive_and_token_based():
    hits = policy.scan_blob("a.md", b"ok line\nsee ZzForbiddenZz.example here\n", FAKE)
    assert len(hits) == 1 and hits[0].startswith("a.md:2:")
    # a substring inside a longer word is not a token match
    assert not policy.scan_blob("b.md", b"xzzforbiddenzzx", FAKE)


def test_output_never_prints_the_token():
    hits = policy.scan_blob("a.md", b"zzforbiddenzz", FAKE)
    assert hits and "zzforbiddenzz" not in hits[0]


def test_binary_metadata_is_scanned():
    blob = b"\x89PNG\r\n\x1a\n\x00\x00junk\x00 creator zzforbiddenzz signing \x00\x01"
    assert policy.scan_blob("img.png", blob, FAKE)


def test_zip_based_documents_are_opened():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("docProps/core.xml", "<dc:creator>zzforbiddenzz</dc:creator>")
    hits = policy.scan_blob("deck.pptx", buf.getvalue(), FAKE)
    assert hits and "deck.pptx!docProps/core.xml" in hits[0]


def test_commit_message_attribution_is_caught():
    msg = "feat: thing\n\nCo-Authored-By: zzforbiddenzz <noreply@example.com>\n"
    assert policy.check_commit(msg, "Dev <dev@example.com>", "abc", FAKE)


def test_bot_author_is_caught():
    out = policy.check_commit("chore: bump", "dependabot[bot] <x@users.noreply.github.com>", "abc", FAKE)
    assert any("automated author" in o for o in out)


def test_human_commit_is_clean():
    assert not policy.check_commit("fix: edge case", "Dev <dev@example.com>", "abc", FAKE)
