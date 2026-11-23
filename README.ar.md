<div align="center">

<img src="docs/assets/banner.png" alt="WireGuard Plus - نفق وايرجارد وأمنيزيا داخل تيليجرام لويندوز وأندرويد" width="100%" />

<h1>WireGuard Plus - نفق وايرجارد وأمنيزيا داخل تيليجرام</h1>

[![Latest Release](https://img.shields.io/github/v/release/AliHaider704/wgplus?style=flat-square&color=1A6BB8)](https://github.com/AliHaider704/wgplus/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/AliHaider704/wgplus/total?style=flat-square&color=1F6F54)](https://github.com/AliHaider704/wgplus/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/AliHaider704/wgplus/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/AliHaider704/wgplus/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-334155?style=flat-square)](LICENSE)
[![Windows 10/11](https://img.shields.io/badge/Windows-10%2F11%20x64-0078D4?style=flat-square&logo=windows&logoColor=white)](https://github.com/AliHaider704/wgplus/releases/latest)
[![Android 5.0+](https://img.shields.io/badge/Android-5.0%2B-3DDC84?style=flat-square&logo=android&logoColor=white)](https://github.com/AliHaider704/wgplus/releases/latest)

**نفق WireGuard و AmneziaWG 1.5 داخل تيليجرام فقط - لتجاوز الحجب وفحص الحزم (DPI) على ويندوز (بدون تعارض مع Tailscale أو الشبكات الأخرى، وبوضع محمول كامل، مع عزل مسار المكالمات لتيليجرام فقط) وعلى أندرويد (بدون روت وبدون استهلاك خانة الـ VPN) مع تمرير المكالمات الصوتية والمرئية.**

<p dir="ltr">
  <a href="README.md">English</a> ·
  <a href="https://github.com/AliHaider704/wgplus/releases/latest">Download Windows / Android</a> ·
  <a href="docs/COMPARISON.md">Compare vs Proxies &amp; VPNs</a> ·
  <a href="docs/USER_GUIDE.md">User Guide</a>
</p>

</div>

---

<div dir="rtl">

## التحميل (`v1.9.0`)

| المنصة | رابط التحميل | المتطلبات | الملاحظات |
|--------|--------------|-----------|-----------|
| **ويندوز (ملف `.exe` مفرد، `17.83 MB`)** | [`WireGuardPlus-Windows-x64.exe`](https://github.com/AliHaider704/wgplus/releases/latest/download/WireGuardPlus-Windows-x64.exe) | ويندوز 10/11 (x64) | تشغيل مباشر، تشفير DPAPI، أيقونة شريط النظام، توجيه معزول للمكالمات |
| **ويندوز المحمول (`.zip`، `6.87 MB`)** | [`WireGuardPlus-Windows-x64-Portable.zip`](https://github.com/AliHaider704/wgplus/releases/latest/download/WireGuardPlus-Windows-x64-Portable.zip) | ويندوز 10/11 (x64)، فلاش/مجلد | يحتوي `portable.flag`، حفظ محلي كامل بدون AppData |
| **أندرويد ARM64 (`5.05 MB` - موصى به)** | [`WireGuardPlus-1.9.0-arm64-v8a.apk`](https://github.com/AliHaider704/wgplus/releases/latest/download/WireGuardPlus-1.9.0-arm64-v8a.apk) | أندرويد 5.0+ (arm64-v8a) | بدون روت عبر LSPatch أو بالروت عبر LSPosed / Vector |
| **أندرويد ARMv7 (`5.02 MB`)** | [`WireGuardPlus-1.9.0-armeabi-v7a.apk`](https://github.com/AliHaider704/wgplus/releases/latest/download/WireGuardPlus-1.9.0-armeabi-v7a.apk) | أندرويد 5.0+ (armeabi-v7a) | للأجهزة ذات معمارية 32 بت |
| **أندرويد الشاملة (`11.29 MB`)** | [`WireGuardPlus-1.9.0.apk`](https://github.com/AliHaider704/wgplus/releases/latest/download/WireGuardPlus-1.9.0.apk) | أندرويد 5.0+ (arm64 + armv7a) | نسخة شاملة متوافقة مع التحديثات التلقائية |

تحقق من تطابق الملفات عبر [`SHA256SUMS.txt`](https://github.com/AliHaider704/wgplus/releases/latest/download/SHA256SUMS.txt)، أو شاهد [فيديو الشرح (`MP4`)](https://github.com/AliHaider704/wgplus/releases/download/v1.7.3/WireGuardPlus-Windows-Walkthrough.mp4)، أو انضم إلى [قناة تيليجرام الرسمية](https://t.me/wgplus_official).

---

## لماذا نفق وايرجارد بلس؟

في الدول التي يُحجب فيها تيليجرام أو يخضع لفحص الحزم العميق مثل **العراق وإيران والأردن** والشبكات المقيدة المشابهة، يضطر المستخدم عادةً للاختيار بين حلّين ناقصين:

- **بروكسيات تيليجرام المجانية (MTProto / SOCKS5):** تُحجب بسرعة، تفرض قنوات إعلانية، لا تصمد أمام الـ DPI، وغالبًا ما تفشل في المكالمات الصوتية والمرئية أو تكشف عنوانك الحقيقي.
- **تطبيقات VPN للنظام كله:** تنصّب تعريفات Wintun أو تشغل خانة الـ VPN الوحيدة (فتتعارض مع Tailscale أو AdGuard أو VPN العمل)، وتبطئ المتصفح والألعاب والتطبيقات المحلية.

**نفق وايرجارد بلس** يحل المشكلتين بتشغيل محرك **WireGuard + AmneziaWG 1.5** (`wireguard-go` + `gVisor`) في مساحة المستخدم لتيليجرام فقط:

| الميزة | وايرجارد بلس (ويندوز + أندرويد) | تطبيق VPN للنظام | بروكسي MTProto / SOCKS5 |
|--------|:--------------------------------:|:----------------:|:-----------------------:|
| **يمرر تيليجرام فقط (الألعاب والمتصفح والتطبيقات البنكية لا تتأثر)** | **نعم** | بصعوبة حسب الاستثناءات | نعم (المحادثات فقط) |
| **بدون روت على أندرويد / بدون استهلاك خانة VPN أو تعارض Tailscale** | **نعم** (توجيه معزول لتيليجرام فقط على ويندوز) | لا | نعم |
| **دعم تعدد نسخ ويندوز (تيليجرام المحمول، AyuGram، 64Gram، Unigram)** | **نعم** | استثناءات يدوية محدودة | يدوي لكل نسخة |
| **مكالمات صوتية ومرئية مشفرة (محول Wintun معزول لويندوز + ممرّات `127.0.0.1` لأندرويد)** | **نعم** | نعم | غير مستقر / ينقطع |
| **تمويه AmneziaWG 1.5 (`I1`-`I5` QUIC) و WARP و DoH مشفر** | **نعم** | نادر | لا |
| **مانع تسريب صارم + جدار حماية `iphlpapi` و Authenticode (لويندوز)** | **نعم** | للنظام كله | لا |
| **بدون قنوات إعلانية أو إجبار اشتراك** | **نعم** | نعم | منتشر في البروكسيات |

اقرأ المقارنة التقنية الكاملة في [صفحة المقارنة (بالإنجليزية)](docs/COMPARISON.md).

---

## لقطات الشاشة والعرض التوضيحي

### نسخة ويندوز (Windows Desktop)

<div align="center">
  <img src="docs/assets/windows-showcase.png" alt="لقطات شاشة WireGuard Plus على ويندوز - النفق والمكالمات، جدار الحماية والوضع الفاتح، AmneziaWG 1.5، والواجهة العربية" width="100%" />
</div>

<details>
<summary><strong>عرض متحرك لواجهة ويندوز (التشغيل بدون مسؤول، تمويه AWG 1.5، الوضع الفاتح، QR والعربية)</strong></summary>

<div align="center">
  <br />
  <img src="docs/assets/windows-demo.gif" alt="عرض متحرك لواجهة ويندوز WireGuard Plus" width="840" />
  <br />
  <sub>تفضّل الفيديو عالي الدقة؟ شاهد أو حمّل <a href="https://github.com/AliHaider704/wgplus/releases/download/v1.7.3/WireGuardPlus-Windows-Walkthrough.mp4">WireGuardPlus-Windows-Walkthrough.mp4</a>.</sub>
</div>

</details>

### نسخة أندرويد (داخل تيليجرام)

<div align="center">
  <img src="docs/assets/screenshots-showcase.png" alt="لقطات شاشة أندرويد WireGuard Plus" width="100%" />
</div>

<details>
<summary><strong>عرض متحرك لواجهة أندرويد (الوضع الداكن والفاتح، DNS المشفر، وتمويه AmneziaWG)</strong></summary>

<div align="center">
  <br />
  <img src="docs/assets/demo.gif" alt="عرض متحرك لتطبيق أندرويد WireGuard Plus" width="380" />
</div>

</details>

---

## آلية العمل

</div>

```mermaid
flowchart LR
    WIN["نسخ تيليجرام على ويندوز<br/>(Telegram Desktop / Portable /<br/>AyuGram / 64Gram / Unigram)"] -->|"127.0.0.1 SOCKS5 + RFC 1929<br/>(جدار حماية iphlpapi)"| GS["محرك gVisor Netstack +<br/>wgbridge-go المشترك"]
    AND["تطبيق تيليجرام على أندرويد<br/>(Telegram / Telegram Plus)"] -->|"بروكسي محلي داخل العملية<br/>(المحادثات والوسائط و tgcalls)"| GS
    GS -->|"WireGuard + AmneziaWG 1.5<br/>(تمويه I1-I5 + DoH)"| EP["خادمك الخاص أو WARP<br/>(نفق مشفر بالكامل)"]
    OTHER["الألعاب، المتصفح، البنوك،<br/>Tailscale و AdGuard"] -->|"اتصال مباشر /<br/>VPN النظام الحالي"| NET["الإنترنت الاعتيادي<br/>(بدون أي تعارض)"]
```

<div dir="rtl">

- **ويندوز:** يكتشف تلقائيًا نسخ **Telegram Desktop** و**النسخ المحمولة Portable** و**AyuGramDesktop** و**64Gram** و**Unigram** و**Forkgram**، ويمرر المحادثات والوسائط عبر `127.0.0.1` المحمي بجدار عمليات `iphlpapi` والتحقق الرقمي Authenticode، بينما يوجّه المكالمات الصوتية والمرئية عبر محول Wintun معزول (`WireGuardPlusCalls`) مقتصر حصريًا على نطاقات تيليجرام الرسمية التسعة (`IPv4`) دون المساس بالمتصفح أو الألعاب أو Tailscale.
- **أندرويد:** يندمج مباشرة داخل **تيليجرام الرسمي** (`org.telegram.messenger` و`.beta` و`.web`)، و**تيليجرام بلس** (`org.telegram.plus`)، و**Nagram** (`xyz.nextalone.nagram`)، و**AyuGram** (`com.radolyn.ayugram`)، و**Telegraph** (`ir.ilmili.telegraph` و`ir.p2021.telegraph`)، و**Telegram Gold** (`org.telegram.gold`)، و**Telegram X** (`org.thunderdog.challegram`)، وأي عميل مبني على `ApplicationLoader` بخطافات آمنة (`XC_MethodHook`) ليعمل عبر LSPosed / Vector / LSPatch ويتعايش مع الإضافات مثل **TeleVip** بدون تعارض.

> مشروع مجتمعي غير رسمي، وليس تابعًا لتيليجرام أو WireGuard أو Cloudflare أو Amnezia.

---

## المميزات الأساسية

- **عزل حقيقي داخل تيليجرام (بدون خانة VPN أو تعارض الشبكات):** يشغّل `wireguard-go` و`gVisor` في مساحة المستخدم (`desktopMode` يرفع طوابير النفق إلى `8192` وتجميع `128` حزمة ونوافذ TCP حتى `16 MB` على الكمبيوتر) بحيث لا يمر أي تطبيق آخر عبر النفق.
- **تمويه AmneziaWG 1.0 / 1.5 (`I1`-`I5`) و Cloudflare WARP:** دعم كامل لقيم `Jc`/`Jmin`/`Jmax` و`S1`-`S4` و`H1`-`H4` وحزم التوقيع `I1`-`I5` (محاكاة QUIC) وبصمة `Reserved` لـ WARP مع زر **+ توليد WARP مجاني (AWG 1.5)** بضغطة واحدة على ويندوز.
- **حماية مدرعة لمنفذ التوجيه والمفاتيح (`v1.9.0`):** على ويندوز، يجمع بين جدار `iphlpapi` والتحقق من توقيع Authenticode (`WinVerifyTrust`) ومصادقة RFC 1929 ومانع التسريب الصارم. وعلى أندرويد، يفرض مصادقة SOCKS5 محليًا، ويتحقق من شهادة توقيع التطبيقات المستدعية في `KeepaliveStatusProvider`، ويلغي التخزين النصي في `WgKeystoreCrypto` (`AndroidKeyStore` أو `0600` AES-256-GCM)، ويفرض منفذ الإغلاق `9` عند تفعيل مانع التسريب، ويشفّر النسخ الاحتياطي المصدّر بكلمة مرور (`wgplus-backup-v1`).
- **مكالمات صوتية ومرئية مستقرة (`v1.9.0`):** على أندرويد، ينشئ ممرّات محلية مخصصة على `127.0.0.1` (`UDP`/`TCP` عبر `voip_relay.go`) لكل خادم مكالمة مع تعطيل P2P تلقائيًا. وعلى ويندوز، ينقل محول `WireGuardPlusCalls` (`Wintun v0.14.1`) حزم مكالمات تيليجرام فقط ضمن 9 نطاقات `IPv4` رسمية؛ مع إبقاء خيار **نظير لنظير: لا أحد** مفعلًا داخل تيليجرام لحماية عنوانك.
- **DNS مشفر (DoH) وتشخيص الأخطاء عبر GitHub:** يدعم `1.1.1.1` و`1.0.0.1` و`8.8.8.8` و`9.9.9.9` أو رابط DoH مخصص مع رفض العناوين المزورة، ويفحص الـ IP الخارجي والدولة وسرعة مراكز بيانات تيليجرام `DC1/DC2/DC4/DC5` وجاهزية UDP، مع نسخ تقرير تشخيصي جاهز للإرسال عبر [نموذج بلاغات GitHub](.github/ISSUE_TEMPLATE/bug_report.yml).
- **تشفير DPAPI والوضع المحمول والنسخ الاحتياطي المشفر:** تُشفّر المفاتيح على ويندوز عبر DPAPI (`CryptProtectData`)، ووضع `portable.flag` يحفظ كل البيانات في `./wgplus-data/`، بينما ملفات `.wgplus` (Argon2id + AES-256-GCM) تنقل إعداداتك بأمان بين الأجهزة. على أندرويد تُحفظ المفاتيح في `AndroidKeyStore` وتُزال المفاتيح الخاصة من أي مشاركة مفتوحة.
- **استمرارية موثوقة وأيقونة One UI وواجهة ثنائية اللغة:** تعافي تلقائي على ويندوز عند السكون وتغيّر الشبكة (`handleNetworkSwitch`) وأيقونة شريط النظام، وحماية صامتة على أندرويد، وأيقونة متجهة تكيفية مع دعم Monochrome لواجهة One UI، وواجهة عربية (RTL) وإنجليزية (LTR) بالوضعين الداكن والفاتح.

---

## التثبيت السريع

### أولًا: ويندوز (خلال دقيقة)

يتطلب **ويندوز 10 أو 11 (x64)**.

1. حمّل [`WireGuardPlus-Windows-x64.exe`](https://github.com/AliHaider704/wgplus/releases/latest/download/WireGuardPlus-Windows-x64.exe) أو فك ضغط [`WireGuardPlus-Windows-x64-Portable.zip`](https://github.com/AliHaider704/wgplus/releases/latest/download/WireGuardPlus-Windows-x64-Portable.zip).
2. شغّل `WireGuardPlus.exe` (ملف واحد جاهز دون تنصيب تعريفات يدوية).
3. أضف خادمك عبر **استيراد `.conf`** أو **استيراد QR** أو **لصق (Ctrl+V)** أو اضغط **+ توليد WARP مجاني (AWG 1.5)** ثم اضغط **اتصال**.
4. من بطاقة **تطبيقات تيليجرام على ويندوز** حدد نسختك (Telegram Desktop أو النسخة المحمولة أو AyuGramDesktop أو 64Gram أو Unigram أو أضف مسارًا يدويًا عبر **+ إضافة نسخة محمولة**) واضغط **تطبيق البروكسي**.
5. لخصوصية المكالمات على الكمبيوتر: اضبط **الإعدادات -> الخصوصية والأمان -> المكالمات -> نظير لنظير: لا أحد** داخل تيليجرام مرة واحدة، ثم اضغط **فحص المسار والمكالمات** للتأكد من الجاهزية.

### ثانيًا: أندرويد (خلال ٣ دقائق، بدون روت أو بالروت)

يتطلب **أندرويد 5.0+** (**أندرويد 11+** للتفعيل الصامت عبر التصحيح اللاسلكي).

1. حمّل [`WireGuardPlus-1.9.0-arm64-v8a.apk`](https://github.com/AliHaider704/wgplus/releases/latest/download/WireGuardPlus-1.9.0-arm64-v8a.apk) (`5.05 MB`) أو [`WireGuardPlus-1.9.0-armeabi-v7a.apk`](https://github.com/AliHaider704/wgplus/releases/latest/download/WireGuardPlus-1.9.0-armeabi-v7a.apk) (`5.02 MB`) أو [`WireGuardPlus-1.9.0.apk`](https://github.com/AliHaider704/wgplus/releases/latest/download/WireGuardPlus-1.9.0.apk) (الشاملة).
2. **بدون روت (LSPatch):** ادمج أي نسخة مدعومة (**Telegram** أو **Telegram Plus** أو **Nagram** أو **AyuGram** أو **Telegraph** أو **Telegram Gold** أو **Telegram X**) عبر [JingMatrix LSPatch](https://github.com/JingMatrix/LSPatch) بوضع **Portable** أو **Local**، ثم ثبّت تيليجرام وافتح تطبيق **نفق وايرجارد بلس** لإكمال ربط التصحيح اللاسلكي ذي الـ 6 أرقام لمرة واحدة.
   - **مع روت (LSPosed / Vector):** فعّل **WireGuard Plus** في **LSPosed / Vector -> Modules** وحدد تطبيقات تيليجرام ثم امنح الروت داخل التطبيق لحماية صامتة.
3. داخل تيليجرام افتح **الإعدادات -> البيانات والتخزين -> إعدادات البروكسي -> نفق وايرجارد** وأضف ملفك واتصل.

التفاصيل الكاملة وحلول المشاكل في [دليل المستخدم](docs/USER_GUIDE.md).

---

## التحقق من الملفات و SmartScreen وشفافية الشبكة (ويندوز)

للتحقق من سلامة ملف ويندوز ومطابقته لملف [`SHA256SUMS.txt`](https://github.com/AliHaider704/wgplus/releases/latest/download/SHA256SUMS.txt) عبر PowerShell:

```powershell
Get-FileHash .\WireGuardPlus-Windows-x64.exe -Algorithm SHA256
```

- **بخصوص تنبيه SmartScreen أو Defender (`!ml`):** لأن المشروع مفتوح المصدر ومجاني بدون شهادة توقيع تجارية مدفوعة، قد يُظهر ويندوز تنبيه SmartScreen عند التشغيل الأول لنسخ Go + Wails الجديدة. الملف **لا يستخدم UPX أو أي أدوات ضغط مشفرة**، ويمكن بناؤه مباشرة من المصدر أو التحقق من سجل البناء الموثّق (SLSA provenance) عبر [`.github/workflows/release-windows.yml`](.github/workflows/release-windows.yml).
- **شفافية الاتصالات الخارجية (صفر تتبع أو تحليلات):** التطبيق لا يتصل بأي خادم تحليلات أو إعلانات؛ جميع اتصالاته الممكنة محصورة بالتالي فقط:

| الغرض | الوجهة | متى يحدث؟ |
|-------|--------|-----------|
| حزم نفق WireGuard / AWG 1.5 المشفرة | عنوان خادم `.conf` الخاص بك (أو WARP) | أثناء الاتصال فقط |
| فك اسم نطاق الخادم عبر DoH المشفر | `1.1.1.1` و `1.0.0.1` و `8.8.8.8` و `9.9.9.9` (أو خادم DoH مخصص) | عند الاتصال بنطاق DNS |
| فحص الـ IP الخارجي ومراكز بيانات تيليجرام و UDP | `one.one.one.one/cdn-cgi/trace` و `1.1.1.1:53` ومراكز `DC1/2/4/5` عبر النفق | فقط عند ضغط **فحص المسار والمكالمات** |
| تسجيل جهاز Cloudflare WARP مجاني | `https://api.cloudflareclient.com/v0a2158/reg` | فقط عند ضغط **+ توليد WARP مجاني** |
| التحقق من التحديثات على GitHub | `https://api.github.com/repos/AliHaider704/wgplus/releases/latest` | عند التشغيل / طلب التحديث |

---

## البناء من المصدر

```powershell
# 1. نسخة ويندوز (يتطلب Go 1.26+ و Wails v2.17.1): يشغّل الاختبارات وينتج dist/*.exe و Portable.zip
powershell -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1

# 2. نسخة أندرويد (يتطلب Go + NDK + gomobile + JDK 21 + Android SDK): ينتج dist/*.apk
powershell -ExecutionPolicy Bypass -File .\scripts\build-wgbridge.ps1
.\gradlew.bat testReleaseUnitTest assembleRelease
```

التفاصيل الكاملة في [دليل البناء](docs/BUILD_GUIDE.md).

---

## التوثيق والملفات

- [المقارنة مع البروكسيات والـ VPN](docs/COMPARISON.md)
- [دليل المستخدم وحل المشاكل](docs/USER_GUIDE.md)
- [دليل البناء](docs/BUILD_GUIDE.md)
- [المعمارية التقنية](docs/ARCHITECTURE.md)
- [نموذج الأمان والخصوصية](docs/SECURITY.md)
- [سجل التغييرات](CHANGELOG.md)
- [المساهمة في المشروع](CONTRIBUTING.md)
- [الإبلاغ عن الثغرات](SECURITY.md)

---

## الشكر والترخيص

مبني على [wireguard-go](https://git.zx2c4.com/wireguard-go) و[gVisor](https://gvisor.dev) و[Wails v2](https://wails.io) و[gomobile](https://pkg.go.dev/golang.org/x/mobile) و[ZXing](https://github.com/zxing/zxing) و[gozxing](https://github.com/makiuchi-d/gozxing) و[libadb-android](https://github.com/MuntashirAkon/libadb-android) و[Conscrypt](https://conscrypt.org/) وبروتوكولات تمويه الحزم من [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go).

الترخيص: [MIT](LICENSE)

</div>
