# Tatar Relay — how it compares

*Authorized security testing only.*

Working with an app that adds **its own encryption layer on top of TLS** is not a
new problem, and there are good tools that touch parts of it. Tatar Relay's point
is not to reinvent them — it's to remove the repetitive glue you write **per
engagement** and turn it into one reusable, config-first workflow that lives
inside Burp.

## The landscape

| Tool | What it's great at | The gap Tatar Relay fills |
|------|--------------------|---------------------------|
| **Hackvertor** (Burp) | Inline tag-based encode/encrypt/decrypt in Burp; custom code via tags | Tag-oriented and per-request; no reusable *profile* per target, no live key capture, no scheme detection, no automatic reseal of ts/nonce/HMAC |
| **CyberChef** | Declarative "recipe" of transforms, huge operation set | Not a proxy; not wired into the Burp intercept/Repeater flow; no live session-key capture; no reseal-in-place |
| **Frida** | Hooks crypto at runtime (great for mobile) | A scripting toolkit, not a Burp editing workflow; you still hand-write the decrypt/edit/re-encrypt loop |
| **Piper / per-cipher BApps** | Pipe requests through external tools / one specific cipher | Point solutions; no general profile + pipeline + detection system |
| **A per-engagement Python script** | Fully custom, fast for one target | Thrown away every time; breaks when the algorithm changes; not shareable |

## Why Tatar Relay

The differentiator is the **combination**, as one package glued to Burp:

1. **Config-first profile** — describe a target once in YAML; reuse it. Drop to a
   Python hook only when YAML isn't enough ("simple is declarative, hard is
   Python — never hit a wall").
2. **Reversible pipeline + reseal** — `decrypt(encrypt(x)) == x` is enforced, and
   re-serialization is explicit (`preserve` / `canonical` / `compact`) so a right
   key doesn't silently break an HMAC.
3. **Request *and* response** decrypt/edit, without leaving Burp.
4. **Live key capture** — a JS hook grabs the per-login session key automatically.
5. **Scheme detection** — a crypto *observer* reports the exact algorithm live and
   flags it when the app changes cipher; `inspect` fingerprints a blob and drafts a
   profile for you.

None of the individual ideas are unheard-of. The *integrated, config-first,
detection-included* version — for the specific problem of app-layer encryption on
top of TLS — is the gap that stays open because generalizing it is thankless
per-engagement work and the audience is niche. That's the space Tatar Relay fills.

> Positioning line: **"CyberChef's recipes meet Burp's Repeater — with live keys
> and cipher detection built in."**

---

# Монгол — харьцуулалт

*Зөвхөн зөвшөөрөлтэй тест.*

TLS дээр **өөрийн шифрлэлт нэмсэн** апптай ажиллах нь шинэ асуудал биш — зарим
хэсгийг нь шийддэг сайн tool-ууд бий. Tatar Relay-гийн зорилго тэдгээрийг дахин
зохиох биш, харин **engagement болгонд** бичдэг давтагдах glue-г арилгаж, Burp
дотор ажилладаг нэг дахин ашиглагдах, config-first урсгал болгох явдал.

## Одоо байгаа tool-ууд

| Tool | Юугаараа сайн | Tatar Relay нөхдөг цоорхой |
|------|---------------|----------------------------|
| **Hackvertor** (Burp) | Burp дотор tag-аар inline encode/encrypt/decrypt | Tag-төвтэй, per-request; target бүрт дахин ашиглагдах *profile* байхгүй, live key барихгүй, схем илрүүлэхгүй, ts/nonce/HMAC reseal автомат биш |
| **CyberChef** | Declarative recipe, асар олон үйлдэл | Proxy биш; Burp intercept/Repeater урсгалд ороогүй; live key барихгүй; reseal-in-place байхгүй |
| **Frida** | Runtime дээр крипто hook (мобайлд сайн) | Scripting toolkit, Burp editing workflow биш; decrypt/edit/encrypt гогцоог гараар бичсэн хэвээр |
| **Piper / нэг cipher BApp** | Гадаад tool руу дамжуулах / нэг тодорхой cipher | Цэгэн шийдэл; ерөнхий profile + pipeline + detection систем биш |
| **Engagement бүрийн Python скрипт** | Бүрэн custom, нэг target-д хурдан | Удаа болгонд хаягддаг; алгоритм солигдоход эвдэрдэг; хуваалцах боломжгүй |

## Яагаад Tatar Relay

Ялгарах гол зүйл нь **хослол** — Burp-д наасан нэг багц:

1. **Config-first profile** — target-ыг нэг удаа YAML-д тодорхойлж дахин ашиглана.
   YAML хүрэлцэхгүй үед л Python hook руу шилжинэ ("энгийнд declarative, хэцүүд
   Python — хана мөргөхгүй").
2. **Урвуутай pipeline + reseal** — `decrypt(encrypt(x)) == x` батлагдсан; дахин
   serialize нь тодорхой (`preserve`/`canonical`/`compact`) тул зөв key байсан ч
   HMAC чимээгүй эвдрэхгүй.
3. **Request ба response** хоёуланг Burp дотроосоо гаралгүй задлаж засна.
4. **Live key capture** — JS hook login бүрийн session key-г автоматаар барина.
5. **Схем илрүүлэлт** — crypto observer алгоритмыг бодитоор хэлж, апп cipher
   солиход шууд сэрэмжлүүлнэ; `inspect` blob-ыг таньж draft profile гаргана.

Санаанууд нь тус тусдаа шинэ биш. Харин **нэгдсэн, config-first, detection-багтсан**
хувилбар — TLS дээрх app-layer шифрлэлтийн тодорхой асуудалд — цоорхой хэвээр байна,
учир нь ерөнхийлөх нь per-engagement талархалгүй ажил, audience нь ниш. Tatar Relay
яг энэ орон зайг нөхдөг.
