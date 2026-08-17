#!/usr/bin/env python3
"""
تحليل سجل اللوق وعرض جميع التفاصيل المتعلقة بجميع الـ IPs.

طرق التشغيل:
  1) من الرابط مباشرة (تحميل ثم تحليل):
     python3 analyze_logs.py http://192.168.100.19/ALL_CSV_TXT.txt
  2) من ملف محلي (بعد التحميل يدوياً):
     python3 analyze_logs.py /مسار/إلى/ALL_CSV_TXT.txt
  3) من الملفات الأربعة (بعد التقسيم):
     python3 analyze_logs.py

المخرجات: log_analysis.json + dashboard.html (جميع التفاصيل: الدولة، الموقع، ISP، الطرق، المسارات، الأكواد، عينة اللوق).
"""
import html as html_module
import json
import os
import re
import sys
import tempfile
import time
import urllib.request
from datetime import datetime

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = _BASE  # مجلد cyber target (نفس مكان الأجزاء الأربعة txt)
NUM_PARTS = 4
OUTPUT_EXT = ".txt"
MAX_SAMPLES_PER_IP = 5
MAX_LINE_LENGTH = 300
# نمط IPv4 (أول ظهور في السطر يُعتبر IP المصدر)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# عناوين خاصة لا نستعلم عنها من API
PRIVATE_IP = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)")
GEO_CACHE = {}  # ip -> { country, city, isp, org, ... }
GEO_DELAY = 0.25  # ثانية بين الطلبات (احترام حد ip-api.com)


def extract_ip(line):
    """استخراج أول عنوان IPv4 من السطر."""
    m = IP_PATTERN.search(line)
    return m.group(0) if m else None


def extract_username_from_path(path):
    """استخراج اسم المستخدم من المسار إن وُجد (مثلاً ?username=admin أو ?user=admin)."""
    if not path or "?" not in path:
        return None
    query = path.split("?", 1)[1]
    for part in query.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().lower()
            v = (v.strip() or "").strip()
            if k in ("username", "user", "login", "uname") and v:
                return v[:100]  # حد معقول
    return None


def parse_log_line(line):
    """
    تحليل سطر اللوق: دعم صيغ CSV الشائعة (ip,date,method,path,status) أو أي سطر فيه فواصل.
    يُرجع قاموس بالحقول المستخرجة أو None.
    """
    line = line.strip()
    if not line or "," not in line:
        return None
    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 2:
        return None
    # أول عمود غالباً IP
    ip = parts[0] if IP_PATTERN.match(parts[0]) else (extract_ip(line) or parts[0])
    out = {"ip": ip, "raw": line}
    # محاولة تفسير الأعمدة: ip, date, method, path, status (أو تشابه)
    if len(parts) >= 5:
        out["date"] = parts[1]
        out["method"] = parts[2].upper() if len(parts[2]) < 10 else parts[2]
        out["path"] = parts[3]
        out["status"] = parts[4]
    elif len(parts) >= 3:
        out["date"] = parts[1]
        out["method"] = parts[2].upper() if len(parts[2]) < 10 else ""
        out["path"] = ""
        out["status"] = ""
    else:
        out["date"] = parts[1] if len(parts) > 1 else ""
        out["method"] = ""
        out["path"] = ""
        out["status"] = ""
    if out.get("path"):
        u = extract_username_from_path(out["path"])
        if u:
            out["username"] = u
    return out


def is_private_ip(ip):
    """هل العنوان من النطاق الخاص (لا نستعلم عنه من API)."""
    return bool(PRIVATE_IP.match(ip)) if ip else True


def fetch_geo_for_ip(ip):
    """جلب الدولة وبيانات الموقع لـ IP من ip-api.com (مجاني، بدون مفتاح)."""
    if not ip or is_private_ip(ip):
        return {"country": "— (خاص)", "city": "", "isp": "", "org": "", "regionName": ""}
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    fields = "status,country,countryCode,regionName,city,isp,org"
    url = f"http://ip-api.com/json/{ip}?fields={fields}&lang=ar"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "LogAnalyzer/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            out = {
                "country": data.get("country") or "—",
                "city": data.get("city") or "",
                "isp": data.get("isp") or "",
                "org": data.get("org") or "",
                "regionName": data.get("regionName") or "",
            }
        else:
            out = {"country": "—", "city": "", "isp": "", "org": "", "regionName": ""}
    except Exception:
        out = {"country": "—", "city": "", "isp": "", "org": "", "regionName": ""}
    GEO_CACHE[ip] = out
    time.sleep(GEO_DELAY)
    return out


def analyze_behavior(item, total_lines):
    """
    تحليل سلوك المهاجم من اللوق: طبيعي أو مشبوه مع الأسباب.
    معايير مشبوهة: نسبة أخطاء عالية، تنوع كبير في المسارات (مسح)، عدد طلبات مرتفع جداً، تكرار POST.
    """
    count = item.get("count", 0)
    statuses = item.get("statuses", {})
    paths = item.get("paths", {})
    methods = item.get("methods", {})
    reasons = []
    error_codes = [s for s in statuses if s and (s.startswith("4") or s.startswith("5"))]
    error_count = sum(statuses.get(s, 0) for s in error_codes)
    error_rate = (error_count / count * 100) if count else 0
    unique_paths = len(paths)
    unique_methods = len(methods)
    if count > 0 and total_lines > 0:
        share = count / total_lines * 100
        if error_rate >= 40:
            reasons.append("نسبة عالية من استجابات الخطأ (4xx/5xx)")
        if unique_paths > 30 and count > 100:
            reasons.append("تنوع غير اعتيادي في المسارات (يشبه المسح)")
        if share > 50 and count > 500:
            reasons.append("حجم نشاط مرتفع جداً مقارنة بباقي اللوق")
        if methods.get("POST", 0) > count * 0.8 and count > 100:
            reasons.append("تركيز على طلبات POST (قد يشير لمحاولات تسجيل دخول متكررة)")

    if reasons:
        return {"label": "مشبوه", "reasons": reasons}
    return {"label": "طبيعي", "reasons": ["نمط النشاط ضمن المعدل الاعتيادي"]}


def get_threat_level(item, total_lines):
    """مستوى الخطر: عالي، متوسط، منخفض بناءً على السلوك وعدد الطلبات."""
    behavior = analyze_behavior(item, total_lines)
    count = item.get("count", 0)
    share = (count / total_lines * 100) if total_lines and total_lines > 0 else 0
    if behavior["label"] == "مشبوه":
        return "عالي"
    if share > 15 or count > 2000:
        return "متوسط"
    return "منخفض"


def enrich_ips_with_geo(ips_list, max_geo=None):
    """إضافة الدولة وجميع البيانات المتعلقة بكل IP. إذا وُجد max_geo نستعلم عن أول max_geo عنوان فقط (لتسريع الملفات الكبيرة)."""
    enriched = []
    for i, item in enumerate(ips_list):
        ip = item.get("ip", "")
        is_private = is_private_ip(ip)
        if max_geo is not None and i >= max_geo:
            geo = {"country": "—", "city": "", "regionName": "", "isp": "", "org": ""}
        else:
            geo = fetch_geo_for_ip(ip)
        enriched.append({
            "ip": ip,
            "count": item.get("count", 0),
            "samples": item.get("samples", []),
            "methods": item.get("methods", {}),
            "paths": item.get("paths", {}),
            "statuses": item.get("statuses", {}),
            "usernames": item.get("usernames", []),
            "country": geo.get("country", "—"),
            "city": geo.get("city", ""),
            "regionName": geo.get("regionName", ""),
            "isp": geo.get("isp", ""),
            "org": geo.get("org", ""),
            "is_private": is_private,
        })
    return enriched


def _process_line(line, ip_data, total_lines_ref):
    """معالجة سطر واحد وتحديث ip_data. نستخرج أول IP في السطر (أي عمود أو داخل النص)."""
    total_lines_ref[0] += 1
    ip = extract_ip(line)
    if not ip:
        return
    if ip not in ip_data:
        ip_data[ip] = {
            "count": 0,
            "samples": [],
            "methods": {},
            "paths": {},
            "statuses": {},
            "usernames": set(),
        }
    d = ip_data[ip]
    d["count"] += 1
    if len(d["samples"]) < MAX_SAMPLES_PER_IP:
        d["samples"].append(line.strip()[:MAX_LINE_LENGTH])
    parsed = parse_log_line(line)
    if parsed:
        if parsed.get("method"):
            d["methods"][parsed["method"]] = d["methods"].get(parsed["method"], 0) + 1
        if parsed.get("path"):
            d["paths"][parsed["path"]] = d["paths"].get(parsed["path"], 0) + 1
        if parsed.get("status"):
            d["statuses"][parsed["status"]] = d["statuses"].get(parsed["status"], 0) + 1
        if parsed.get("username"):
            d["usernames"].add(parsed["username"])


def analyze_stream(line_iter, report_every=500000):
    """تحليل أي مصدر أسطر (ملف واحد أو أكثر) وإرجاع نفس بنية analyze_parts."""
    ip_data = {}
    total_lines_ref = [0]
    for i, line in enumerate(line_iter):
        _process_line(line, ip_data, total_lines_ref)
        if report_every and (i + 1) % report_every == 0:
            print(f"  معالجة: {(i+1):,} سطر، {len(ip_data):,} IP فريد...")
    total_lines = total_lines_ref[0]
    sorted_ips = []
    for ip, d in sorted(ip_data.items(), key=lambda x: -x[1]["count"]):
        sorted_ips.append({
            "ip": ip,
            "count": d["count"],
            "samples": d["samples"],
            "methods": d["methods"],
            "paths": d["paths"],
            "statuses": d["statuses"],
            "usernames": list(d.get("usernames", set())),
        })
    return {
        "total_lines": total_lines,
        "unique_ips": len(ip_data),
        "ips": sorted_ips,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def analyze_parts():
    """قراءة الأجزاء الأربعة وتجميع إحصائيات لكل IP مع تحليل بنية اللوق (طرق، مسارات، أكواد)."""
    part_files = [
        os.path.join(OUTPUT_DIR, f"part_{i}_of_{NUM_PARTS}{OUTPUT_EXT}")
        for i in range(1, NUM_PARTS + 1)
    ]
    def line_iter():
        for path in part_files:
            if not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    yield line
    return analyze_stream(line_iter(), report_every=500000)


def analyze_single_file(filepath, report_every=500000, max_lines=None):
    """تحليل ملف لوق واحد (سطر بسطر). إذا وُجد max_lines نقرأ هذا العدد فقط (مفيد للملفات الضخمة)."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        if max_lines is None:
            return analyze_stream(f, report_every=report_every)
        def limited():
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                yield line
        return analyze_stream(limited(), report_every=report_every)


def load_split_result():
    """تحميل نتيجة التقسيم إن وُجدت."""
    path = os.path.join(OUTPUT_DIR, "split_result.json")
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def write_dashboard(split_result, log_analysis):
    """كتابة صفحة الداشبورد (تقسيم + تحليل اللوق)."""
    # قسم التقسيم
    split_html = ""
    if split_result and split_result.get("parts"):
        parts = split_result["parts"]
        total_b = split_result["total_bytes"]
        output_dir = split_result.get("output_dir", OUTPUT_DIR)
        ts = split_result.get("timestamp", "")

        def size_fmt(b):
            if b >= 1024**3:
                return f"{b / 1024**3:.2f} GB"
            return f"{b / 1024**2:.2f} MB"

        parts_cards = ""
        for p in parts:
            sz = p["size_bytes"]
            pct = (sz / total_b * 100) if total_b else 0
            parts_cards += f"""
            <div class="card">
                <div class="card-icon">📄</div>
                <div class="card-body">
                    <h3>{p["name"]}</h3>
                    <p class="size">{size_fmt(sz)}</p>
                    <div class="bar"><div class="bar-fill" style="width:{pct}%"></div></div>
                </div>
            </div>"""

        split_html = f"""
        <section class="section">
            <h2>نتيجة التقسيم</h2>
            <div class="summary">
                <div class="summary-item">
                    <span class="label">إجمالي الحجم</span>
                    <span class="value">{size_fmt(total_b)}</span>
                </div>
                <div class="summary-item">
                    <span class="label">عدد الأجزاء</span>
                    <span class="value">{len(parts)}</span>
                </div>
                <div class="summary-item path-item">
                    <span class="label">مسار الحفظ</span>
                    <span class="path">{output_dir}</span>
                </div>
            </div>
            <div class="cards">{parts_cards}</div>
        </section>"""

    # قسم تحليل اللوق — العناوين الخارجية أولاً (ثم الداخلية)
    log_html = ""
    if log_analysis and log_analysis.get("ips"):
        ips = log_analysis["ips"]
        public_ips = [i for i in ips if not i.get("is_private", True)]
        private_ips = [i for i in ips if i.get("is_private", True)]
        total_lines = log_analysis.get("total_lines", 0)
        unique_ips = log_analysis.get("unique_ips", 0)
        ts_log = log_analysis.get("timestamp", "")
        max_count = max((item["count"] for item in ips), default=1)

        summary_cards = f"""
            <div class="analysis-summary-card">
                <span class="analysis-summary-icon">📊</span>
                <div>
                    <span class="analysis-summary-value">{total_lines:,}</span>
                    <span class="analysis-summary-label">إجمالي أحداث اللوق</span>
                </div>
            </div>
            <div class="analysis-summary-card highlight-external">
                <span class="analysis-summary-icon">🌍</span>
                <div>
                    <span class="analysis-summary-value">{len(public_ips):,}</span>
                    <span class="analysis-summary-label">عناوين خارجية (من الإنترنت)</span>
                </div>
            </div>
            <div class="analysis-summary-card">
                <span class="analysis-summary-icon">🏠</span>
                <div>
                    <span class="analysis-summary-value">{len(private_ips):,}</span>
                    <span class="analysis-summary-label">عناوين داخلية (شبكة محلية)</span>
                </div>
            </div>
            <div class="analysis-summary-card">
                <span class="analysis-summary-icon">📌</span>
                <div>
                    <span class="analysis-summary-value">{public_ips[0]['ip'] if public_ips else ('—' if not private_ips else 'لا توجد عناوين خارجية')}</span>
                    <span class="analysis-summary-label">أعلى IP خارجي من حيث النشاط</span>
                </div>
            </div>"""
        normal_count = sum(1 for i in public_ips if analyze_behavior(i, total_lines)["label"] == "طبيعي")
        suspicious_count = len(public_ips) - normal_count
        if public_ips:
            summary_cards += f"""
            <div class="analysis-summary-card behavior-summary-normal">
                <span class="analysis-summary-icon">✓</span>
                <div>
                    <span class="analysis-summary-value">{normal_count}</span>
                    <span class="analysis-summary-label">دخول طبيعي</span>
                </div>
            </div>
            <div class="analysis-summary-card behavior-summary-suspicious">
                <span class="analysis-summary-icon">!</span>
                <div>
                    <span class="analysis-summary-value">{suspicious_count}</span>
                    <span class="analysis-summary-label">هجوم / مشبوه</span>
                </div>
            </div>"""

        # جدول الملخص: اليوزر، نوع الهجوم، مستوى التهديد، عدد مرات الدخول، ...
        all_ips_for_table = ips
        table_rows = ""
        for rank, item in enumerate(all_ips_for_table[:200], 1):
            behavior = analyze_behavior(item, total_lines)
            attack_type = "هجوم" if behavior["label"] == "مشبوه" else "دخول طبيعي"
            attack_class = "attack-badge" if behavior["label"] == "مشبوه" else "normal-badge"
            threat = get_threat_level(item, total_lines)
            threat_class = "threat-high" if threat == "عالي" else ("threat-mid" if threat == "متوسط" else "threat-low")
            usernames = item.get("usernames") or []
            users_display = ", ".join(usernames[:5]) if usernames else "—"
            if usernames and len(usernames) > 5:
                users_display += " …"
            # اليوزر: إن وُجد اسم مستخدم نعرضه، وإلا نعرض IP كمصدر
            user_display = users_display if usernames else item["ip"]
            location_str = (item.get("country") or "—") + (f'، {item.get("city") or ""}' if item.get("city") else "")
            activity_summary = []
            if item.get("methods"):
                top_m = sorted(item["methods"].items(), key=lambda x: -x[1])[:3]
                activity_summary.append(" ".join(f"{m}({c})" for m, c in top_m))
            if item.get("paths"):
                top_p = sorted(item["paths"].items(), key=lambda x: -x[1])[:2]
                activity_summary.append(" مسارات: " + ", ".join(p for p, _ in top_p))
            activity_str = " | ".join(activity_summary) if activity_summary else "—"
            table_rows += f"""
            <tr>
                <td class="table-rank">{rank}</td>
                <td class="table-user">{html_module.escape(user_display)}</td>
                <td class="table-ip">{item["ip"]}</td>
                <td><span class="badge {attack_class}">{attack_type}</span></td>
                <td><span class="badge {threat_class}">{threat}</span></td>
                <td class="table-count">{item["count"]:,}</td>
                <td class="table-country">{html_module.escape(location_str[:40])}</td>
                <td class="table-activity">{html_module.escape(activity_str[:60])}</td>
            </tr>"""

        summary_table_html = f"""
            <div class="log-summary-table-wrap">
                <h3 class="log-summary-table-title">اليوزر · نوع الهجوم · مستوى التهديد</h3>
                <table class="log-summary-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>اليوزر</th>
                            <th>IP</th>
                            <th>نوع الهجوم</th>
                            <th>مستوى التهديد</th>
                            <th>عدد الطلبات</th>
                            <th>الدولة</th>
                            <th>تحليل الحركة</th>
                        </tr>
                    </thead>
                    <tbody>{table_rows}</tbody>
                </table>
            </div>"""

        # قسم OSINT — من osint_report.json إن وُجد
        osint_section_html = ""
        soc_dir = os.path.dirname(os.path.abspath(__file__))
        osint_path = os.path.join(soc_dir, "osint_report.json")
        if os.path.isfile(osint_path):
            try:
                with open(osint_path, "r", encoding="utf-8") as of:
                    osint_data = json.load(of)
                osint_list = osint_data.get("osint", [])
                # ترتيب: عامة أولاً ثم حسب عدد الطلبات تنازلياً
                public_osint = [o for o in osint_list if o.get("ip") and not (o.get("geo") or {}).get("country", "").startswith("— (خاص)")]
                private_osint = [o for o in osint_list if o.get("ip") and (o.get("geo") or {}).get("country", "").startswith("— (خاص)")]
                ordered_osint = sorted(public_osint, key=lambda x: -x.get("count", 0)) + sorted(private_osint, key=lambda x: -x.get("count", 0))
                osint_rows = ""
                for rank, r in enumerate(ordered_osint[:150], 1):
                    ip = r.get("ip", "")
                    count = r.get("count", 0)
                    geo = r.get("geo", {})
                    whois = r.get("whois", {})
                    country = html_module.escape(geo.get("country", "—"))
                    city = html_module.escape(geo.get("city", "") or "—")
                    isp = html_module.escape((geo.get("isp") or "—")[:35])
                    org = html_module.escape((geo.get("org") or "—")[:35])
                    rdns = html_module.escape((r.get("reverse_dns") or "—")[:40])
                    netname = html_module.escape((whois.get("netname") or "—")[:25])
                    osint_rows += f"""
                    <tr>
                        <td class="osint-rank">{rank}</td>
                        <td class="osint-ip">{ip}</td>
                        <td class="osint-count">{count:,}</td>
                        <td class="osint-country">{country}</td>
                        <td class="osint-city">{city}</td>
                        <td class="osint-isp">{isp}</td>
                        <td class="osint-org">{org}</td>
                        <td class="osint-rdns">{rdns}</td>
                        <td class="osint-netname">{netname}</td>
                    </tr>"""
                osint_section_html = f"""
            <div class="osint-section">
                <h3 class="osint-title">قسم OSINT — استخبارات المصادر المفتوحة</h3>
                <p class="osint-desc">الدولة، المدينة، ISP، المنظمة، Reverse DNS، NetName (WHOIS). المصدَر: {html_module.escape(osint_data.get("source", "osint_report.json"))}. لتحديث البيانات: python3 osint_report.py</p>
                <div class="osint-table-wrap">
                    <table class="osint-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>IP</th>
                                <th>عدد الطلبات</th>
                                <th>الدولة</th>
                                <th>المدينة</th>
                                <th>ISP</th>
                                <th>المنظمة</th>
                                <th>Reverse DNS</th>
                                <th>NetName</th>
                            </tr>
                        </thead>
                        <tbody>{osint_rows}</tbody>
                    </table>
                </div>
            </div>"""
            except Exception:
                pass

        ip_cards = ""
        max_ips_show = 500
        ips_show = public_ips[:max_ips_show]
        for rank, item in enumerate(ips_show, 1):
            ip = item["ip"]
            count = item["count"]
            country = item.get("country", "—")
            city = item.get("city", "")
            region = item.get("regionName", "")
            isp = item.get("isp", "")
            org = item.get("org", "")
            pct = (count / max_count * 100) if max_count else 0
            share = (count / total_lines * 100) if total_lines else 0
            behavior = analyze_behavior(item, total_lines)
            is_private = item.get("is_private", True)

            location_str = country + (f'، {city}' if city else '') + (f'، {region}' if region and region != city else '')
            location_html = f'<div class="location-block"><span class="location-icon">📍</span><span class="location-text">الموقع: {location_str}</span></div>'
            isp_html = f'<div class="isp-block"><span class="isp-label">مزود الخدمة (ISP):</span> <span class="isp-value">{isp or "—"}</span></div>'
            behavior_class = "behavior-normal" if behavior["label"] == "طبيعي" else "behavior-suspicious"
            behavior_display = "دخول طبيعي" if behavior["label"] == "طبيعي" else "هجوم"
            behavior_reasons = "; ".join(behavior["reasons"]).replace("&", "&amp;").replace("<", "&lt;")
            threat = get_threat_level(item, total_lines)
            threat_class = "threat-high" if threat == "عالي" else ("threat-mid" if threat == "متوسط" else "threat-low")
            if is_private:
                data_rows = f"""
                <tr><td colspan="2" class="private-notice">عنوان خاص (شبكة داخلية) — لا يوجد موقع عام لهذا النوع. البيانات أدناه من تحليل اللوق فقط.</td></tr>
                """
                for label, val in [
                    ("الدولة / الموقع", "— (عنوان خاص)"),
                    ("مزود الخدمة (ISP)", "—"),
                    ("المنظمة (Org)", "—"),
                ]:
                    data_rows += f"<tr><td class=\"data-label\">{label}</td><td class=\"data-value\">{val}</td></tr>"
            else:
                data_rows = ""
                for label, val in [
                    ("الدولة", country),
                    ("المدينة", city or "—"),
                    ("المنطقة", region or "—"),
                    ("مزود الخدمة (ISP)", isp or "—"),
                    ("المنظمة (Org)", (org if (org and org != isp) else "—")),
                ]:
                    data_rows += f"<tr><td class=\"data-label\">{label}</td><td class=\"data-value\">{val}</td></tr>"

            methods = item.get("methods", {})
            paths = item.get("paths", {})
            statuses = item.get("statuses", {})
            log_analysis_rows = ""
            if methods:
                top_m = sorted(methods.items(), key=lambda x: -x[1])[:5]
                log_analysis_rows += f"<tr><td class=\"data-label\">الطرق (من اللوق)</td><td class=\"data-value\">{', '.join(f'{m}({c})' for m, c in top_m)}</td></tr>"
            if paths:
                top_p = sorted(paths.items(), key=lambda x: -x[1])[:5]
                log_analysis_rows += f"<tr><td class=\"data-label\">أهم المسارات</td><td class=\"data-value\">{', '.join(f'{p}({c})' for p, c in top_p)}</td></tr>"
            if statuses:
                top_s = sorted(statuses.items(), key=lambda x: -x[1])[:5]
                log_analysis_rows += f"<tr><td class=\"data-label\">أكواد الاستجابة</td><td class=\"data-value\">{', '.join(f'{s}({c})' for s, c in top_s)}</td></tr>"
            if log_analysis_rows:
                data_rows += f"<tr><td colspan=\"2\" class=\"log-analysis-header\">تحليل من بنية اللوق (CSV)</td></tr>{log_analysis_rows}"

            samples = item.get("samples", [])
            samples_html = ""
            for s in samples[:5]:
                esc = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                samples_html += f"<div class=\"log-sample-line\">{esc}</div>"

            ip_cards += f"""
            <div class="ip-analysis-card">
                <div class="ip-card-header">
                    <span class="ip-rank">#{rank}</span>
                    <span class="ip-address">{ip}</span>
                    <span class="badge {attack_class}">{behavior_display}</span>
                    <span class="badge {threat_class}">مستوى التهديد: {threat}</span>
                    <span class="ip-events">{count:,} حدث</span>
                    <span class="ip-share">({share:.1f}% من الإجمالي)</span>
                </div>
                <div class="ip-card-bar"><div class="ip-card-bar-fill" style="width:{pct}%"></div></div>
                <div class="ip-card-meta">
                    {location_html}
                    {isp_html}
                    <div class="behavior-block {behavior_class}">
                        <span class="behavior-label">نوع الهجوم:</span>
                        <span class="behavior-value">{behavior_display}</span>
                        <span class="behavior-reasons">{behavior_reasons}</span>
                    </div>
                </div>
                <div class="ip-card-body">
                    <div class="ip-data-block">
                        <h4>الموقع والبيانات الجغرافية ومزود الخدمة</h4>
                        <table class="ip-data-table">
                            <tbody>{data_rows}</tbody>
                        </table>
                    </div>
                    <div class="ip-log-block">
                        <h4>عينة من سجلات اللوق لهذا العنوان</h4>
                        <div class="ip-log-samples">{samples_html or "—"}</div>
                    </div>
                </div>
            </div>"""

        log_html = f"""
        <section class="section log-section">
            <h2>تحليل سجل اللوق — العناوين الخارجية (من الإنترنت)</h2>
            <p class="section-desc">عرض العناوين الخارجية مع: الموقع (الدولة والمدينة)، مزود الخدمة، تحليل سلوك المهاجم (هجوم / دخول طبيعي)، وتفاصيل تحليل اللوق. العناوين الداخلية في الأسفل.</p>
            <div class="analysis-summary">{summary_cards}</div>
            {summary_table_html}
            {osint_section_html}
            <div class="ip-cards-list">{ip_cards}</div>
            {('<p class="no-external-msg">لم يُعثر على عناوين خارجية في هذا اللوق. جميع العناوين داخلية (شبكة محلية). راجع قسم العناوين الداخلية أدناه.</p>' if not public_ips and ips else '')}
            {f'<p class="timestamp">عرض أول {len(ips_show):,} عنوان خارجي من أصل {len(public_ips):,}. لجميع العناوين استخدم log_analysis.json</p>' if len(public_ips) > max_ips_show else ''}
            {('<div class="internal-ips-section"><h4>العناوين الداخلية (شبكة محلية) — ' + str(len(private_ips)) + ' عنوان</h4><div class="internal-ips-list">' + ''.join('<span class="internal-ip">' + i['ip'] + '</span> <span class="internal-count">' + f'{i["count"]:,}' + ' حدث</span> ' for i in private_ips[:100]) + '</div></div>') if private_ips else ''}
            <p class="timestamp">آخر تحديث: {ts_log}</p>
        </section>"""
    else:
        log_html = """
        <section class="section log-section">
            <h2>تحليل اللوق — عناوين IP والبيانات المرتبطة</h2>
            <p class="no-data">لا توجد بيانات لوق. تأكد من وجود الملفات الأربعة (part_1_of_4.txt … part_4_of_4.txt) في مجلد cyber target ثم شغّل: python3 analyze_logs.py</p>
        </section>"""

    html = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>نتيجة التقسيم وتحليل اللوق | Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'IBM Plex Sans Arabic', sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
            min-height: 100vh;
            color: #e2e8f0;
            padding: 2rem;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        h1 {{ text-align: center; font-size: 1.75rem; margin-bottom: 0.5rem; font-weight: 700; }}
        .subtitle {{ text-align: center; color: #94a3b8; margin-bottom: 2rem; font-size: 0.95rem; }}
        .section {{ margin-bottom: 3rem; }}
        .section h2 {{ font-size: 1.25rem; margin-bottom: 1rem; color: #38bdf8; }}
        .log-section {{ background: rgba(30, 41, 59, 0.4); border: 1px solid #475569; border-radius: 12px; padding: 1.25rem; }}
        .section-desc {{ color: #94a3b8; font-size: 0.9rem; margin-bottom: 1.25rem; }}
        .analysis-summary {{ display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }}
        .analysis-summary-card {{
            background: rgba(56, 189, 248, 0.12); border: 1px solid #38bdf8; border-radius: 10px;
            padding: 1rem 1.25rem; display: flex; align-items: center; gap: 0.75rem; min-width: 180px;
        }}
        .analysis-summary-icon {{ font-size: 1.5rem; }}
        .analysis-summary-value {{ display: block; font-size: 1.1rem; font-weight: 700; color: #38bdf8; }}
        .analysis-summary-label {{ display: block; font-size: 0.8rem; color: #94a3b8; }}
        .analysis-summary-card.highlight-external {{ border-color: #22c55e; background: rgba(34, 197, 94, 0.12); }}
        .analysis-summary-card.highlight-external .analysis-summary-value {{ color: #22c55e; }}
        .analysis-summary-card.behavior-summary-normal .analysis-summary-value {{ color: #22c55e; }}
        .analysis-summary-card.behavior-summary-suspicious .analysis-summary-value {{ color: #f87171; }}
        .analysis-summary-card.behavior-summary-suspicious {{ border-color: #ef4444; background: rgba(239, 68, 68, 0.08); }}
        .ip-cards-list {{ display: flex; flex-direction: column; gap: 1.25rem; }}
        .internal-ips-section {{ margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid #334155; }}
        .internal-ips-section h4 {{ font-size: 0.95rem; color: #94a3b8; margin-bottom: 0.5rem; }}
        .internal-ips-list {{ font-size: 0.85rem; color: #64748b; }}
        .internal-ip {{ font-family: ui-monospace, monospace; color: #94a3b8; margin-left: 0.5rem; }}
        .internal-count {{ color: #64748b; margin-left: 0.25rem; }}
        .no-external-msg {{ color: #fbbf24; padding: 1rem; background: rgba(251, 191, 36, 0.1); border-radius: 8px; }}
        .log-summary-table-wrap {{ overflow-x: auto; margin-bottom: 2rem; border: 1px solid #334155; border-radius: 10px; background: rgba(15, 23, 42, 0.6); }}
        .log-summary-table-title {{ font-size: 1rem; color: #38bdf8; margin-bottom: 0.75rem; padding: 0 1rem; padding-top: 1rem; }}
        .log-summary-table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        .log-summary-table th, .log-summary-table td {{ padding: 0.6rem 0.75rem; text-align: right; border-bottom: 1px solid #334155; }}
        .log-summary-table th {{ background: #1e293b; color: #38bdf8; font-weight: 600; }}
        .log-summary-table tbody tr:hover {{ background: rgba(56, 189, 248, 0.08); }}
        .log-summary-table .table-rank {{ color: #94a3b8; width: 40px; }}
        .log-summary-table .table-ip {{ font-family: ui-monospace, monospace; color: #38bdf8; font-weight: 600; }}
        .log-summary-table .table-count {{ font-weight: 700; color: #e2e8f0; }}
        .log-summary-table .table-activity {{ max-width: 200px; color: #94a3b8; font-size: 0.85rem; }}
        .badge {{ display: inline-block; padding: 0.25rem 0.6rem; border-radius: 6px; font-size: 0.85rem; font-weight: 600; }}
        .badge.attack-badge {{ background: rgba(239, 68, 68, 0.25); color: #f87171; border: 1px solid #ef4444; }}
        .badge.normal-badge {{ background: rgba(34, 197, 94, 0.25); color: #22c55e; border: 1px solid #22c55e; }}
        .badge.threat-high {{ background: rgba(239, 68, 68, 0.3); color: #fca5a5; border: 1px solid #ef4444; font-weight: 700; }}
        .badge.threat-mid {{ background: rgba(245, 158, 11, 0.3); color: #fcd34d; border: 1px solid #f59e0b; font-weight: 700; }}
        .badge.threat-low {{ background: rgba(34, 197, 94, 0.25); color: #86efac; border: 1px solid #22c55e; font-weight: 600; }}
        .log-summary-table .table-user {{ font-weight: 600; color: #e2e8f0; }}
        .osint-section {{ margin-bottom: 2rem; border: 1px solid #334155; border-radius: 10px; background: rgba(15, 23, 42, 0.5); padding: 1rem; }}
        .osint-title {{ font-size: 1.1rem; color: #22c55e; margin-bottom: 0.35rem; }}
        .osint-desc {{ color: #94a3b8; font-size: 0.85rem; margin-bottom: 1rem; }}
        .osint-table-wrap {{ overflow-x: auto; }}
        .osint-table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
        .osint-table th, .osint-table td {{ padding: 0.5rem 0.6rem; text-align: right; border-bottom: 1px solid #334155; }}
        .osint-table th {{ background: #1e293b; color: #22c55e; font-weight: 600; }}
        .osint-table tbody tr:hover {{ background: rgba(34, 197, 94, 0.06); }}
        .osint-table .osint-rank {{ color: #64748b; width: 36px; }}
        .osint-table .osint-ip {{ font-family: ui-monospace, monospace; color: #38bdf8; font-weight: 600; }}
        .osint-table .osint-count {{ font-weight: 700; color: #e2e8f0; }}
        .ip-analysis-card {{
            background: rgba(30, 41, 59, 0.8); border: 1px solid #334155; border-radius: 12px; overflow: hidden;
        }}
        .ip-card-header {{ display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 1rem; padding: 1rem 1.25rem; background: rgba(15, 23, 42, 0.5); }}
        .ip-rank {{ background: #38bdf8; color: #0f172a; font-weight: 700; padding: 0.2rem 0.5rem; border-radius: 6px; font-size: 0.85rem; }}
        .ip-address {{ font-family: ui-monospace, monospace; font-weight: 600; color: #38bdf8; font-size: 1.05rem; }}
        .ip-events {{ color: #e2e8f0; font-weight: 600; }}
        .ip-share {{ color: #94a3b8; font-size: 0.9rem; }}
        .ip-card-bar {{ height: 6px; background: #334155; }}
        .ip-card-bar-fill {{ height: 100%; background: linear-gradient(90deg, #38bdf8, #818cf8); transition: width 0.3s; }}
        .ip-card-meta {{ padding: 0.75rem 1.25rem; background: rgba(15, 23, 42, 0.4); border-bottom: 1px solid #334155; display: flex; flex-wrap: wrap; gap: 1rem; align-items: center; }}
        .location-block {{ display: flex; align-items: center; gap: 0.35rem; }}
        .location-icon {{ font-size: 1.1rem; }}
        .location-text {{ color: #38bdf8; font-weight: 600; }}
        .isp-block {{ color: #94a3b8; font-size: 0.9rem; }}
        .isp-value {{ color: #e2e8f0; font-weight: 500; }}
        .behavior-block {{ padding: 0.35rem 0.75rem; border-radius: 8px; font-size: 0.9rem; }}
        .behavior-block .behavior-label {{ margin-left: 0.25rem; }}
        .behavior-block.behavior-normal {{ background: rgba(34, 197, 94, 0.2); border: 1px solid #22c55e; color: #22c55e; }}
        .behavior-block.behavior-suspicious {{ background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #f87171; }}
        .behavior-reasons {{ display: block; font-size: 0.8rem; color: #94a3b8; margin-top: 0.25rem; }}
        .ip-card-body {{ padding: 1rem 1.25rem; display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; }}
        @media (max-width: 768px) {{ .ip-card-body {{ grid-template-columns: 1fr; }} }}
        .ip-data-block h4, .ip-log-block h4 {{ font-size: 0.9rem; color: #94a3b8; margin-bottom: 0.5rem; }}
        .ip-data-table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        .ip-data-table .data-label {{ color: #64748b; padding: 0.35rem 0; width: 140px; }}
        .ip-data-table .data-value {{ color: #e2e8f0; }}
        .ip-data-table .private-notice {{ color: #fbbf24; font-size: 0.85rem; padding: 0.5rem 0; }}
        .ip-data-table .log-analysis-header {{ color: #38bdf8; font-weight: 600; padding-top: 0.75rem; }}
        .ip-log-block {{ border-right: 1px solid #334155; padding-right: 1rem; }}
        @media (max-width: 768px) {{ .ip-log-block {{ border-right: none; padding-right: 0; border-top: 1px solid #334155; padding-top: 1rem; }} }}
        .ip-log-samples {{ background: #0f172a; border-radius: 8px; padding: 0.75rem; font-family: ui-monospace, monospace; font-size: 0.8rem; color: #94a3b8; max-height: 160px; overflow-y: auto; }}
        .log-sample-line {{ margin-bottom: 0.25rem; word-break: break-all; }}
        .summary {{
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 1.5rem;
            display: flex;
            flex-wrap: wrap;
            gap: 1.5rem;
            align-items: center;
        }}
        .summary-item {{ display: flex; flex-direction: column; gap: 0.25rem; }}
        .summary-item .label {{ color: #94a3b8; font-size: 0.85rem; }}
        .summary-item .value {{ font-size: 1.25rem; font-weight: 600; color: #38bdf8; }}
        .path {{ word-break: break-all; font-size: 0.85rem; color: #94a3b8; }}
        .path-item {{ flex: 1; min-width: 200px; }}
        .cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 1rem; }}
        .card {{
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 1rem;
            display: flex;
            align-items: flex-start;
            gap: 0.75rem;
        }}
        .card-icon {{ font-size: 1.5rem; }}
        .card-body {{ flex: 1; min-width: 0; }}
        .card h3 {{ font-size: 0.95rem; margin-bottom: 0.35rem; word-break: break-all; }}
        .card .size {{ color: #38bdf8; font-weight: 600; font-size: 1rem; }}
        .bar {{ height: 6px; background: #334155; border-radius: 3px; margin-top: 0.5rem; overflow: hidden; }}
        .bar-fill {{ height: 100%; background: linear-gradient(90deg, #38bdf8, #818cf8); border-radius: 3px; }}
        .table-wrap {{ overflow-x: auto; border-radius: 10px; border: 1px solid #334155; background: rgba(30, 41, 59, 0.6); }}
        .log-table {{ width: 100%; border-collapse: collapse; }}
        .log-table th, .log-table td {{ padding: 0.75rem 1rem; text-align: right; border-bottom: 1px solid #334155; }}
        .log-table th {{ color: #94a3b8; font-weight: 600; font-size: 0.9rem; }}
        .log-table tbody tr:hover {{ background: rgba(56, 189, 248, 0.08); }}
        .ip-cell {{ font-family: ui-monospace, monospace; color: #38bdf8; }}
        .country-cell {{ font-weight: 600; color: #a5b4fc; }}
        .count-cell {{ font-weight: 600; }}
        .samples-cell {{ max-width: 420px; }}
        .samples-wrap {{ font-size: 0.8rem; color: #94a3b8; max-height: 160px; overflow-y: auto; }}
        .geo-line {{ margin-bottom: 0.25rem; }}
        .geo-line.country {{ font-weight: 600; color: #a5b4fc; }}
        .samples-label {{ margin-top: 0.5rem; margin-bottom: 0.25rem; color: #64748b; font-size: 0.75rem; }}
        .sample-line {{ margin-bottom: 0.35rem; word-break: break-all; }}
        .sample-line.text-muted {{ color: #64748b; }}
        .no-data {{ color: #94a3b8; padding: 1rem; }}
        .timestamp {{ color: #64748b; font-size: 0.8rem; margin-top: 1rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>نتيجة التقسيم وتحليل اللوق</h1>
        <p class="subtitle">تقسيم الملف إلى أجزاء + استخراج IP والدولة وجميع البيانات المرتبطة</p>
        {log_html}
        {split_html}
    </div>
</body>
</html>"""

    soc_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")
    with open(soc_path, "w", encoding="utf-8") as f:
        f.write(html)
    out_path = os.path.join(OUTPUT_DIR, "dashboard.html")
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)
    except OSError:
        out_path = soc_path
    return out_path


def write_dashboard_external_only(split_result, log_analysis, output_path=None):
    """
    إنشاء داشبورد HTML يعرض تحليل اللوق بالكامل: عناوين خارجية (مع دولة وISP) وعناوين داخلية (مع وسم داخلي)،
    مع رسوم بيانية، مستوى الخطر، وسلوك الهجوم. النتيجة بصيغة HTML مرتبة.
    """
    from collections import Counter
    all_ips = list(log_analysis["ips"]) if (log_analysis and log_analysis.get("ips")) else []
    public_ips = [i for i in all_ips if not i.get("is_private", True)]
    private_ips = [i for i in all_ips if i.get("is_private", True)]
    total_lines = log_analysis.get("total_lines", 0) if log_analysis else 0
    ts_log = log_analysis.get("timestamp", "") if log_analysis else ""

    # إحصائيات للرسوم — من كل العناوين (خارجية + داخلية)
    countries = Counter(i.get("country", "—") for i in public_ips)
    if private_ips and not public_ips:
        country_labels = ["داخلي (شبكة محلية)"]
        country_data = [len(private_ips)]
    elif private_ips:
        country_labels = list(countries.keys())[:19] + ["داخلي (شبكة محلية)"]
        country_data = [countries[c] for c in country_labels[:-1]] + [len(private_ips)]
    else:
        country_labels = list(countries.keys())[:20]
        country_data = [countries[c] for c in country_labels]
    threat_counts = Counter()
    for i in all_ips:
        threat_counts[get_threat_level(i, total_lines)] += 1
    max_count = max((i["count"] for i in all_ips), default=1)
    top_ips_for_chart = sorted(all_ips, key=lambda x: -x["count"])[:15]

    threat_labels = ["عالي", "متوسط", "منخفض"]
    threat_data = [threat_counts.get(t, 0) for t in threat_labels]
    top_ip_labels = [item["ip"] for item in top_ips_for_chart]
    top_ip_data = [item["count"] for item in top_ips_for_chart]

    # قسم التقسيم (إن وُجد)
    split_html = ""
    if split_result and split_result.get("parts"):
        parts = split_result["parts"]
        total_b = split_result["total_bytes"]
        output_dir = split_result.get("output_dir", OUTPUT_DIR)
        ts_split = split_result.get("timestamp", "")

        def size_fmt(b):
            if b >= 1024**3:
                return f"{b / 1024**3:.2f} GB"
            return f"{b / 1024**2:.2f} MB"

        parts_cards = ""
        for p in parts:
            sz = p["size_bytes"]
            pct = (sz / total_b * 100) if total_b else 0
            parts_cards += f'<div class="card"><div class="card-icon">📄</div><div class="card-body"><h3>{p["name"]}</h3><p class="size">{size_fmt(sz)}</p><div class="bar"><div class="bar-fill" style="width:{pct}%"></div></div></div></div>'
        split_html = f"""
        <section class="section">
            <h2>نتيجة التقسيم (4 أجزاء × ~1 GB)</h2>
            <div class="summary"><div class="summary-item"><span class="label">إجمالي الحجم</span><span class="value">{size_fmt(total_b)}</span></div><div class="summary-item"><span class="label">عدد الأجزاء</span><span class="value">{len(parts)}</span></div><div class="summary-item path-item"><span class="label">مسار الحفظ</span><span class="path">{output_dir}</span></div></div>
            <div class="cards">{parts_cards}</div>
        </section>"""

    # رسوم بيانية (Chart.js)
    charts_js = f"""
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
      document.addEventListener('DOMContentLoaded', function() {{
        var rtl = document.documentElement.dir === 'rtl';
        new Chart(document.getElementById('chartCountries'), {{
          type: 'pie',
          data: {{
            labels: {json.dumps(country_labels, ensure_ascii=False)},
            datasets: [{{ data: {country_data}, backgroundColor: ['#38bdf8','#818cf8','#22c55e','#f59e0b','#ef4444','#ec4899','#14b8a6','#a855f7','#64748b','#f97316','#06b6d4','#84cc16','#e879f9','#0ea5e9','#6366f1'] }}]
          }},
          options: {{ responsive: true, plugins: {{ legend: {{ position: 'left' }} }} }}
        }});
        new Chart(document.getElementById('chartThreat'), {{
          type: 'bar',
          data: {{
            labels: {json.dumps(threat_labels, ensure_ascii=False)},
            datasets: [{{ label: 'عدد العناوين', data: {threat_data}, backgroundColor: ['#ef4444','#f59e0b','#22c55e'] }}]
          }},
          options: {{ indexAxis: 'y', responsive: true, plugins: {{ legend: {{ display: false }} }} }}
        }});
        new Chart(document.getElementById('chartTopIPs'), {{
          type: 'bar',
          data: {{
            labels: {json.dumps(top_ip_labels)},
            datasets: [{{ label: 'عدد الطلبات', data: {top_ip_data}, backgroundColor: '#38bdf8' }}]
          }},
          options: {{ responsive: true, plugins: {{ legend: {{ display: false }} }} }}
        }});
      }});
    </script>"""

    # بطاقات جميع العناوين (خارجية أولاً ثم داخلية)، تحليل صحيح للوق
    ip_cards = ""
    for rank, item in enumerate(all_ips[:500], 1):
        ip = item["ip"]
        count = item["count"]
        is_private = item.get("is_private", True)
        country = item.get("country", "—") if not is_private else "—"
        city = item.get("city", "") if not is_private else ""
        region = item.get("regionName", "") if not is_private else ""
        isp = item.get("isp", "") if not is_private else ""
        org = item.get("org", "") if not is_private else ""
        pct = (count / max_count * 100) if max_count else 0
        share = (count / total_lines * 100) if total_lines else 0
        behavior = analyze_behavior(item, total_lines)
        threat = get_threat_level(item, total_lines)
        threat_class = "threat-high" if threat == "عالي" else ("threat-mid" if threat == "متوسط" else "threat-low")
        behavior_class = "behavior-normal" if behavior["label"] == "طبيعي" else "behavior-suspicious"
        behavior_reasons = "; ".join(behavior["reasons"]).replace("&", "&amp;").replace("<", "&lt;")

        if is_private:
            data_rows = '<tr><td colspan="2" class="private-notice">عنوان داخلي (شبكة محلية) — لا يوجد موقع عام. البيانات من تحليل اللوق فقط.</td></tr>'
            data_rows += '<tr><td class="data-label">النوع</td><td class="data-value">داخلي</td></tr>'
        else:
            data_rows = ""
            for label, val in [
                ("الدولة", country),
                ("المدينة", city or "—"),
                ("المنطقة", region or "—"),
                ("مزود الخدمة (ISP)", isp or "—"),
                ("المنظمة (Org)", (org if (org and org != isp) else "—")),
            ]:
                data_rows += f'<tr><td class="data-label">{label}</td><td class="data-value">{val}</td></tr>'
        methods = item.get("methods", {})
        paths = item.get("paths", {})
        statuses = item.get("statuses", {})
        if methods:
            top_m = sorted(methods.items(), key=lambda x: -x[1])[:5]
            data_rows += f'<tr><td class="data-label">الطرق (HTTP)</td><td class="data-value">{", ".join(f"{m}({c})" for m, c in top_m)}</td></tr>'
        if paths:
            top_p = sorted(paths.items(), key=lambda x: -x[1])[:5]
            data_rows += f'<tr><td class="data-label">أهم المسارات</td><td class="data-value">{", ".join(f"{p}({c})" for p, c in top_p)}</td></tr>'
        if statuses:
            top_s = sorted(statuses.items(), key=lambda x: -x[1])[:5]
            data_rows += f'<tr><td class="data-label">أكواد الاستجابة</td><td class="data-value">{", ".join(f"{s}({c})" for s, c in top_s)}</td></tr>'

        samples_html = ""
        for s in item.get("samples", [])[:5]:
            esc = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            samples_html += f'<div class="log-sample-line">{esc}</div>'

        if is_private:
            location_display = '<span class="location-text internal-badge">🏠 عنوان داخلي (شبكة محلية)</span>'
            isp_display = '<span class="isp-value">—</span>'
        else:
            location_display = f'<span class="location-text">📍 {country}{f"، {city}" if city else ""}</span>'
            isp_display = f'<span class="isp-value">مزود الخدمة: {isp or "—"}</span>'

        ip_cards += f"""
            <div class="ip-analysis-card">
                <div class="ip-card-header">
                    <span class="ip-rank">#{rank}</span>
                    <span class="ip-address">{ip}</span>
                    <span class="threat-badge {threat_class}">{threat}</span>
                    <span class="ip-events">{count:,} حدث</span>
                    <span class="ip-share">({share:.1f}%)</span>
                </div>
                <div class="ip-card-bar"><div class="ip-card-bar-fill" style="width:{pct}%"></div></div>
                <div class="ip-card-meta">
                    {location_display}
                    {isp_display}
                    <div class="behavior-block {behavior_class}">
                        <span class="behavior-label">سلوك الهجوم:</span>
                        <span class="behavior-value">{behavior["label"]}</span>
                        <span class="behavior-reasons">{behavior_reasons}</span>
                    </div>
                </div>
                <div class="ip-card-body">
                    <div class="ip-data-block">
                        <h4>معلومات الهجوم والموقع</h4>
                        <table class="ip-data-table"><tbody>{data_rows}</tbody></table>
                    </div>
                    <div class="ip-log-block">
                        <h4>عينة من اللوق</h4>
                        <div class="ip-log-samples">{samples_html or "—"}</div>
                    </div>
                </div>
            </div>"""

    normal_count = sum(1 for i in all_ips if analyze_behavior(i, total_lines)["label"] == "طبيعي")
    suspicious_count = len(all_ips) - normal_count
    high_threat = sum(1 for i in all_ips if get_threat_level(i, total_lines) == "عالي")
    mid_threat = sum(1 for i in all_ips if get_threat_level(i, total_lines) == "متوسط")
    low_threat = len(all_ips) - high_threat - mid_threat

    summary_cards = f"""
            <div class="analysis-summary-card"><span class="analysis-summary-icon">📊</span><div><span class="analysis-summary-value">{total_lines:,}</span><span class="analysis-summary-label">إجمالي أحداث اللوق</span></div></div>
            <div class="analysis-summary-card highlight-external"><span class="analysis-summary-icon">🌍</span><div><span class="analysis-summary-value">{len(public_ips):,}</span><span class="analysis-summary-label">عناوين خارجية</span></div></div>
            <div class="analysis-summary-card"><span class="analysis-summary-icon">🏠</span><div><span class="analysis-summary-value">{len(private_ips):,}</span><span class="analysis-summary-label">عناوين داخلية</span></div></div>
            <div class="analysis-summary-card"><span class="analysis-summary-icon">🔴</span><div><span class="analysis-summary-value">{high_threat}</span><span class="analysis-summary-label">مستوى خطر عالي</span></div></div>
            <div class="analysis-summary-card"><span class="analysis-summary-icon">🟠</span><div><span class="analysis-summary-value">{mid_threat}</span><span class="analysis-summary-label">مستوى خطر متوسط</span></div></div>
            <div class="analysis-summary-card"><span class="analysis-summary-icon">🟢</span><div><span class="analysis-summary-value">{low_threat}</span><span class="analysis-summary-label">مستوى خطر منخفض</span></div></div>
            <div class="analysis-summary-card behavior-summary-suspicious"><span class="analysis-summary-icon">!</span><div><span class="analysis-summary-value">{suspicious_count}</span><span class="analysis-summary-label">سلوك مشبوه</span></div></div>
            <div class="analysis-summary-card behavior-summary-normal"><span class="analysis-summary-icon">✓</span><div><span class="analysis-summary-value">{normal_count}</span><span class="analysis-summary-label">سلوك طبيعي</span></div></div>"""

    log_section = f"""
        <section class="section log-section">
            <h2>تحليل أمني — جميع العناوين (خارجية وداخلية)</h2>
            <p class="section-desc">تحليل اللوق بالطريقة الصحيحة: الدولة، مزود الخدمة، مستوى الخطر، سلوك الهجوم. العناوين الخارجية مع موقعها، والداخلية مُوسومة (داخلي).</p>
            <div class="analysis-summary">{summary_cards}</div>
            <div class="charts-row">
                <div class="chart-box"><h4>توزيع الدول / داخلي</h4><canvas id="chartCountries"></canvas></div>
                <div class="chart-box"><h4>مستوى الخطر</h4><canvas id="chartThreat"></canvas></div>
                <div class="chart-box chart-wide"><h4>أعلى 15 IP من حيث الطلبات</h4><canvas id="chartTopIPs"></canvas></div>
            </div>
            <div class="ip-cards-list">{ip_cards}</div>
            <p class="timestamp">آخر تحديث: {ts_log} — عرض {min(len(all_ips), 500)} عنوان (خارجي + داخلي).</p>
        </section>"""

    html = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>داشبورد تحليل اللوق — تحليل أمني كامل | SOC</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'IBM Plex Sans Arabic', sans-serif; background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%); min-height: 100vh; color: #e2e8f0; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ text-align: center; font-size: 1.75rem; margin-bottom: 0.5rem; font-weight: 700; }}
        .subtitle {{ text-align: center; color: #94a3b8; margin-bottom: 2rem; font-size: 0.95rem; }}
        .section {{ margin-bottom: 3rem; }}
        .section h2 {{ font-size: 1.25rem; margin-bottom: 1rem; color: #38bdf8; }}
        .log-section {{ background: rgba(30, 41, 59, 0.4); border: 1px solid #475569; border-radius: 12px; padding: 1.25rem; }}
        .section-desc {{ color: #94a3b8; font-size: 0.9rem; margin-bottom: 1.25rem; }}
        .analysis-summary {{ display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }}
        .analysis-summary-card {{ background: rgba(56, 189, 248, 0.12); border: 1px solid #38bdf8; border-radius: 10px; padding: 1rem 1.25rem; display: flex; align-items: center; gap: 0.75rem; min-width: 160px; }}
        .analysis-summary-card .analysis-summary-value {{ display: block; font-size: 1.1rem; font-weight: 700; color: #38bdf8; }}
        .analysis-summary-card.highlight-external {{ border-color: #22c55e; background: rgba(34, 197, 94, 0.12); }}
        .analysis-summary-card.highlight-external .analysis-summary-value {{ color: #22c55e; }}
        .analysis-summary-card.behavior-summary-normal .analysis-summary-value {{ color: #22c55e; }}
        .analysis-summary-card.behavior-summary-suspicious {{ border-color: #ef4444; background: rgba(239, 68, 68, 0.08); }}
        .analysis-summary-card.behavior-summary-suspicious .analysis-summary-value {{ color: #f87171; }}
        .charts-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem; }}
        .chart-box {{ background: rgba(30, 41, 59, 0.8); border: 1px solid #334155; border-radius: 12px; padding: 1rem; min-height: 280px; }}
        .chart-box.chart-wide {{ grid-column: 1 / -1; min-height: 320px; }}
        .chart-box h4 {{ color: #94a3b8; margin-bottom: 0.75rem; font-size: 0.95rem; }}
        .ip-cards-list {{ display: flex; flex-direction: column; gap: 1.25rem; }}
        .ip-analysis-card {{ background: rgba(30, 41, 59, 0.8); border: 1px solid #334155; border-radius: 12px; overflow: hidden; }}
        .ip-card-header {{ display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 1rem; padding: 1rem 1.25rem; background: rgba(15, 23, 42, 0.5); }}
        .ip-rank {{ background: #38bdf8; color: #0f172a; font-weight: 700; padding: 0.2rem 0.5rem; border-radius: 6px; font-size: 0.85rem; }}
        .ip-address {{ font-family: ui-monospace, monospace; font-weight: 600; color: #38bdf8; font-size: 1.05rem; }}
        .threat-badge {{ padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.8rem; font-weight: 700; }}
        .threat-badge.threat-high {{ background: #ef4444; color: #fff; }}
        .threat-badge.threat-mid {{ background: #f59e0b; color: #0f172a; }}
        .threat-badge.threat-low {{ background: #22c55e; color: #fff; }}
        .ip-events {{ color: #e2e8f0; font-weight: 600; }}
        .ip-share {{ color: #94a3b8; font-size: 0.9rem; }}
        .ip-card-bar {{ height: 6px; background: #334155; }}
        .ip-card-bar-fill {{ height: 100%; background: linear-gradient(90deg, #38bdf8, #818cf8); }}
        .ip-card-meta {{ padding: 0.75rem 1.25rem; background: rgba(15, 23, 42, 0.4); border-bottom: 1px solid #334155; display: flex; flex-wrap: wrap; gap: 1rem; align-items: center; }}
        .location-text {{ color: #38bdf8; font-weight: 600; }}
        .isp-value {{ color: #94a3b8; font-size: 0.9rem; }}
        .behavior-block {{ padding: 0.35rem 0.75rem; border-radius: 8px; font-size: 0.9rem; }}
        .behavior-block.behavior-normal {{ background: rgba(34, 197, 94, 0.2); border: 1px solid #22c55e; color: #22c55e; }}
        .behavior-block.behavior-suspicious {{ background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #f87171; }}
        .behavior-reasons {{ display: block; font-size: 0.8rem; color: #94a3b8; margin-top: 0.25rem; }}
        .ip-card-body {{ padding: 1rem 1.25rem; display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; }}
        .ip-data-block h4, .ip-log-block h4 {{ font-size: 0.9rem; color: #94a3b8; margin-bottom: 0.5rem; }}
        .ip-data-table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        .ip-data-table .data-label {{ color: #64748b; padding: 0.35rem 0; width: 140px; }}
        .ip-data-table .data-value {{ color: #e2e8f0; }}
        .ip-log-samples {{ background: #0f172a; border-radius: 8px; padding: 0.75rem; font-family: ui-monospace, monospace; font-size: 0.8rem; color: #94a3b8; max-height: 160px; overflow-y: auto; }}
        .log-sample-line {{ margin-bottom: 0.25rem; word-break: break-all; }}
        .summary {{ background: rgba(30, 41, 59, 0.8); border: 1px solid #334155; border-radius: 12px; padding: 1.25rem 1.5rem; margin-bottom: 1.5rem; display: flex; flex-wrap: wrap; gap: 1.5rem; align-items: center; }}
        .summary-item {{ display: flex; flex-direction: column; gap: 0.25rem; }}
        .summary-item .label {{ color: #94a3b8; font-size: 0.85rem; }}
        .summary-item .value {{ font-size: 1.25rem; font-weight: 600; color: #38bdf8; }}
        .path {{ word-break: break-all; font-size: 0.85rem; color: #94a3b8; }}
        .path-item {{ flex: 1; min-width: 200px; }}
        .cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 1rem; }}
        .card {{ background: rgba(30, 41, 59, 0.6); border: 1px solid #334155; border-radius: 10px; padding: 1rem; display: flex; align-items: flex-start; gap: 0.75rem; }}
        .card-icon {{ font-size: 1.5rem; }}
        .card-body {{ flex: 1; min-width: 0; }}
        .card h3 {{ font-size: 0.95rem; margin-bottom: 0.35rem; word-break: break-all; }}
        .card .size {{ color: #38bdf8; font-weight: 600; font-size: 1rem; }}
        .bar {{ height: 6px; background: #334155; border-radius: 3px; margin-top: 0.5rem; overflow: hidden; }}
        .bar-fill {{ height: 100%; background: linear-gradient(90deg, #38bdf8, #818cf8); border-radius: 3px; }}
        .no-data {{ color: #94a3b8; padding: 1rem; }}
        .timestamp {{ color: #64748b; font-size: 0.8rem; margin-top: 1rem; }}
        .private-notice {{ color: #fbbf24; font-size: 0.85rem; padding: 0.5rem 0; }}
        .internal-badge {{ color: #94a3b8; }}
        @media (max-width: 768px) {{ .charts-row {{ grid-template-columns: 1fr; }} .chart-box.chart-wide {{ grid-column: 1; }} .ip-card-body {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
    <div class="container">
        <h1>داشبورد تحليل اللوق — تحليل أمني كامل</h1>
        <p class="subtitle">تقسيم الملف 4 أجزاء × 1 GB، تحليل أمني، مستوى الخطر، سلوك الهجوم، ورسم بياني (خارجية + داخلية)</p>
        {log_section if all_ips else '<section class="section log-section"><p class="no-data">لا توجد عناوين في اللوق. تأكد من ملفات الأجزاء (part_1_of_4.txt …) ثم شغّل التحليل.</p></section>'}
        {split_html}
    </div>
    {charts_js if all_ips else ""}
</body>
</html>"""

    out_path = output_path or os.path.join(OUTPUT_DIR, "dashboard_external.html")
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
    except OSError:
        pass
    soc_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_external.html")
    with open(soc_path, "w", encoding="utf-8") as f:
        f.write(html)
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)
    except OSError:
        out_path = soc_path
    return out_path


def _download_log(url, dest_path, chunk=4 * 1024 * 1024):
    """تحميل ملف اللوق من الرابط (دفعات) للحفاظ على الذاكرة."""
    req = urllib.request.Request(url, headers={"User-Agent": "LogAnalyzer/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        with open(dest_path, "wb") as f:
            total = 0
            last_printed = 0
            while True:
                data = r.read(chunk)
                if not data:
                    break
                f.write(data)
                total += len(data)
                if total - last_printed >= 50 * 1024 * 1024:
                    print(f"  تحميل: {total / (1024*1024):.1f} MB...")
                    last_printed = total
    if total > 0:
        print(f"  تم التحميل: {total / (1024*1024):.1f} MB")
    return dest_path


def main():
    log_analysis = None
    source = sys.argv[1] if len(sys.argv) > 1 else None

    if source:
        if source.startswith("http://") or source.startswith("https://"):
            print(f"جاري تحميل سجل اللوق من: {source}")
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
            tmp.close()
            try:
                _download_log(source, tmp.name)
                print("جاري تحليل الملف (جميع التفاصيل لكل IP)...")
                log_analysis = analyze_single_file(tmp.name)
            except OSError as e:
                print(f"  فشل التحميل: {e}")
                print("  تأكد من الاتصال بالشبكة (192.168.100.19) أو حمّل الملف محلياً ثم شغّل:")
                print("  python3 analyze_logs.py /مسار/إلى/ALL_CSV_TXT.txt")
                log_analysis = {"ips": [], "total_lines": 0, "unique_ips": 0, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            except Exception as e:
                print(f"  خطأ: {e}")
                log_analysis = {"ips": [], "total_lines": 0, "unique_ips": 0, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            finally:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass
        elif os.path.isfile(source):
            print(f"جاري تحليل ملف اللوق: {source}")
            log_analysis = analyze_single_file(source)
        else:
            print(f"الملف غير موجود: {source}")
            log_analysis = {"ips": [], "total_lines": 0, "unique_ips": 0, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    else:
        print("جاري تحليل اللوق من الملفات الأربعة...")
        if any(
            os.path.isfile(os.path.join(OUTPUT_DIR, f"part_{i}_of_{NUM_PARTS}{OUTPUT_EXT}"))
            for i in range(1, NUM_PARTS + 1)
        ):
            log_analysis = analyze_parts()
        else:
            print("  لم تُعثر على ملفات الأجزاء في:", OUTPUT_DIR)
            log_analysis = {"ips": [], "total_lines": 0, "unique_ips": 0, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    if log_analysis and log_analysis.get("ips"):
        print("  جاري إضافة الدولة وبيانات الموقع لكل IP...")
        log_analysis["ips"] = enrich_ips_with_geo(log_analysis["ips"])
        path = os.path.join(OUTPUT_DIR, "log_analysis.json")
        try:
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(log_analysis, f, ensure_ascii=False, indent=2)
        except OSError:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log_analysis.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(log_analysis, f, ensure_ascii=False, indent=2)
        print(f"  إجمالي الأسطر: {log_analysis['total_lines']:,}")
        print(f"  عناوين IP فريدة: {log_analysis['unique_ips']:,}")
        print(f"  تم الحفظ: {path}")

    split_result = load_split_result()
    dashboard_path = write_dashboard(split_result, log_analysis)
    print(f"تم إنشاء الداشبورد: {dashboard_path}")
    print("افتح dashboard.html لعرض نتيجة التقسيم وتحليل اللوق.")


if __name__ == "__main__":
    main()
