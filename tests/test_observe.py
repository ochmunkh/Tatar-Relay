import json
import os
import tempfile

from tatar_relay.capture import ObservationLog


def test_observation_dedupe_and_new_flag():
    log = ObservationLog()
    o1 = {"lib": "WebCrypto", "api": "encrypt", "algorithm": "AES-GCM",
          "mode": "GCM", "keyLen": 32, "ivLen": 12, "tagLen": 16}
    is_new, summ = log.record(o1)
    assert is_new is True
    assert "AES-GCM" in summ and "12B nonce" in summ and "32B key" in summ
    # same scheme again -> not new
    assert log.record(dict(o1))[0] is False
    # changed algorithm -> new scheme (the "algorithm changed" alarm)
    o2 = dict(o1); o2["algorithm"] = "ChaCha20-Poly1305"
    assert log.record(o2)[0] is True
    assert len(log.schemes()) == 2


def test_observation_jsonl_written():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "obs.jsonl")
        log = ObservationLog(path=p)
        log.record({"lib": "evp-passphrase", "api": "AES.encrypt", "algorithm": "AES",
                    "mode": "CBC", "keyLen": 32, "ivLen": 16})
        with open(p) as f:
            rows = [json.loads(x) for x in f if x.strip()]
        assert len(rows) == 1 and rows[0]["mode"] == "CBC"
