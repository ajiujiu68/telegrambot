#!/usr/bin/env python3
"""
Telegram IP 查询机器人（中文优化版）
支持 IPv4 / IPv6：地理位置、网络所有者、ASN、路由、注册信息、风险信号
适配 Koyeb / Render / Fly.io / Oracle Cloud 等 7x24 运行环境
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any

import httpx
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
)
from telegram.helpers import escape_markdown

# ============================================================
# 配置区 —— 全部从环境变量读取，不要硬编码 Token
# ============================================================

BOT_TOKEN = os.getenv("BOT_TOKEN", "")

# 可选 API Key（不填也能用，会显示“未配置 Key”）
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
IPQS_KEY = os.getenv("IPQS_KEY", "")

HTTP_TIMEOUT = httpx.Timeout(12.0, connect=8.0)

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


# ============================================================
# 健康检查 HTTP 服务（给 Koyeb / Render / Fly.io 等平台使用）
# ============================================================

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        # 关闭健康检查访问日志，避免刷屏
        return


def start_health_server() -> None:
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), HealthHandler)
    logger.info("健康检查服务已启动：0.0.0.0:%s", port)
    server.serve_forever()


# ============================================================
# 数据源查询函数
# ============================================================

async def fetch_geo(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    """地理位置 + ISP + 组织 + AS 号（ip-api.com，无需 Key，中文返回）"""
    try:
        resp = await client.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": "status,message,country,countryCode,regionName,city,isp,org,as,asname,proxy,hosting,mobile,query",
                "lang": "zh-CN",
            },
        )
        data = resp.json()
        if data.get("status") == "fail":
            return {"error": data.get("message", "查询失败")}
        return data
    except Exception as e:
        logger.warning("ip-api.com 失败: %s", e)
        return {"error": str(e)}


async def fetch_asn(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    """ASN 与网络所有者（ipinfo.io，Token 可选）"""
    if not IPINFO_TOKEN:
        return {"skipped": "未配置 IPINFO_TOKEN"}
    try:
        resp = await client.get(
            f"https://ipinfo.io/{ip}/json",
            params={"token": IPINFO_TOKEN},
        )
        return resp.json()
    except Exception as e:
        logger.warning("ipinfo.io 失败: %s", e)
        return {"error": str(e)}


async def fetch_routing(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    """BGP 路由状态（RIPEstat，免费非商业）"""
    try:
        resp = await client.get(
            "https://stat.ripe.net/data/routing-status/data.json",
            params={"resource": ip, "min_peers_seeing": 1},
        )
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}"}
        return resp.json()
    except Exception as e:
        logger.warning("RIPEstat 失败: %s", e)
        return {"error": str(e)}


async def fetch_rdap(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    """注册信息（RDAP）"""
    try:
        resp = await client.get(
            f"https://rdap.db.ripe.net/ip/{ip}",
            headers={"Accept": "application/rdap+json"},
        )
        if resp.status_code == 404:
            return {"error": "该 IP 未找到 RDAP 记录"}
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}"}
        return resp.json()
    except Exception as e:
        logger.warning("RDAP 失败: %s", e)
        return {"error": str(e)}


async def fetch_abuse(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    """滥用报告（AbuseIPDB，需要 Key）"""
    if not ABUSEIPDB_KEY:
        return {"skipped": "未配置 ABUSEIPDB_KEY"}
    try:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}"}
        return resp.json()
    except Exception as e:
        logger.warning("AbuseIPDB 失败: %s", e)
        return {"error": str(e)}


async def fetch_ipqs(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    """欺诈评分 / 代理 / VPN / Tor（IPQualityScore，需要 Key）"""
    if not IPQS_KEY:
        return {"skipped": "未配置 IPQS_KEY"}
    try:
        resp = await client.get(
            f"https://www.ipqualityscore.com/api/json/ip/{IPQS_KEY}/{ip}",
            params={"strictness": 0, "allow_public_access_points": "true"},
        )
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}"}
        return resp.json()
    except Exception as e:
        logger.warning("IPQS 失败: %s", e)
        return {"error": str(e)}


# ============================================================
# 并发查询主入口
# ============================================================

async def query_all(ip: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        results = await asyncio.gather(
            fetch_geo(client, ip),
            fetch_asn(client, ip),
            fetch_routing(client, ip),
            fetch_rdap(client, ip),
            fetch_abuse(client, ip),
            fetch_ipqs(client, ip),
            return_exceptions=True,
        )

    keys = ["geo", "asn", "routing", "rdap", "abuse", "ipqs"]
    output: dict[str, Any] = {}
    for key, value in zip(keys, results):
        if isinstance(value, Exception):
            output[key] = {"error": str(value)}
        else:
            output[key] = value
    return output


# ============================================================
# 结果格式化
# ============================================================

def safe(value: Any, default: str = "—") -> str:
    if value is None or value == "":
        return default
    return str(value)


def format_result(ip: str, data: dict[str, Any]) -> str:
    geo = data.get("geo", {})
    asn = data.get("asn", {})
    routing = data.get("routing", {})
    rdap = data.get("rdap", {})
    abuse = data.get("abuse", {})
    ipqs = data.get("ipqs", {})

    lines: list[str] = []

    # 标题
    lines.append(f"*🔍 IP 查询结果*  `{escape_markdown(ip, version=2)}`")
    lines.append("")

    # 地理位置
    if "error" in geo:
        lines.append(f"*📍 地理位置*  ⚠️ {escape_markdown(safe(geo.get('error')), version=2)}")
    else:
        country = safe(geo.get("country"))
        region = safe(geo.get("regionName"))
        city = safe(geo.get("city"))
        isp = safe(geo.get("isp"))
        lines.append(
            f"*📍 地理位置*  {escape_markdown(f'{country} · {region} · {city}', version=2)}"
        )
        lines.append(f"*🏢 网络运营商*  {escape_markdown(isp, version=2)}")
    lines.append("")

    # ASN / 网络所有者
    if "error" in asn:
        lines.append(f"*🔗 ASN*  ⚠️ {escape_markdown(safe(asn.get('error')), version=2)}")
    elif "skipped" in asn:
        as_field = geo.get("as", "")
        org = geo.get("org", "")
        if as_field or org:
            lines.append(f"*🔗 ASN*  {escape_markdown(safe(as_field, org), version=2)}")
            lines.append(f"*🏢 网络所有者*  {escape_markdown(safe(org), version=2)}")
        else:
            lines.append(f"*🔗 ASN*  未配置 IPINFO_TOKEN，且 ip-api 无 AS 数据")
    else:
        org = safe(asn.get("org"))
        lines.append(f"*🔗 ASN / 所有者*  {escape_markdown(org, version=2)}")
    lines.append("")

    # 路由
    routing_data = routing.get("data", {}) if isinstance(routing, dict) else {}
    if "error" in routing:
        lines.append(f"*🛰️ 路由*  ⚠️ {escape_markdown(safe(routing.get('error')), version=2)}")
    else:
        visibility = routing_data.get("visibility", {})
        seen = visibility.get("ris_peers_seeing", "—")
        total = visibility.get("total_ris_peers", "—")
        origins = routing_data.get("origins", [])
        origin_str = ", ".join(
            f"{o.get('origin', '?')} ({o.get('prefix', '?')})" for o in origins[:5]
        ) if origins else "—"
        lines.append(f"*🛰️ BGP 路由可见性*  {seen}/{total} 个 RIS 节点")
        lines.append(f"*路由起源*  {escape_markdown(origin_str, version=2)}")
    lines.append("")

    # RDAP 注册信息
    if "error" in rdap:
        lines.append(f"*📋 注册信息*  ⚠️ {escape_markdown(safe(rdap.get('error')), version=2)}")
    else:
        handle = safe(rdap.get("handle"))
        name = safe(rdap.get("name"))
        start = safe(rdap.get("startAddress"))
        end = safe(rdap.get("endAddress"))
        lines.append(f"*📋 注册信息*  {escape_markdown(name or handle, version=2)}")
        lines.append(f"*地址段*  `{escape_markdown(f'{start} - {end}', version=2)}`")
        abuse_contacts = [
            e for e in rdap.get("entities", [])
            if "abuse" in (e.get("roles") or [])
        ]
        if abuse_contacts:
            vcard = abuse_contacts[0].get("vcardArray", [])
            email = ""
            for item in (vcard[1] if len(vcard) > 1 else []):
                if item[0] == "email":
                    email = item[3]
                    break
            if email:
                lines.append(f"*滥用联系人*  `{escape_markdown(email, version=2)}`")
    lines.append("")

    # 风险信号
    lines.append("*🛡️ 风险信号*")

    abuse_data = abuse.get("data", {}) if isinstance(abuse, dict) else {}
    if "error" in abuse:
        lines.append(f"  • AbuseIPDB  ⚠️ {escape_markdown(safe(abuse.get('error')), version=2)}")
    elif "skipped" in abuse:
        lines.append("  • AbuseIPDB  _未配置 Key_")
    else:
        score = abuse_data.get("abuseConfidenceScore", "—")
        reports = abuse_data.get("totalReports", 0)
        lines.append(f"  • 滥用置信度  *{score}*/100  （90天内 {reports} 次报告）")

    if "error" in ipqs:
        lines.append(f"  • IPQS  ⚠️ {escape_markdown(safe(ipqs.get('error')), version=2)}")
    elif "skipped" in ipqs:
        lines.append("  • IPQS  _未配置 Key_")
    else:
        fraud = ipqs.get("fraud_score", "—")
        proxy = "是" if ipqs.get("proxy") else "否"
        vpn = "是" if ipqs.get("vpn") else "否"
        tor = "是" if ipqs.get("tor") else "否"
        lines.append(f"  • 欺诈评分  *{fraud}*/100")
        lines.append(f"  • 代理 / VPN / Tor  {proxy} / {vpn} / {tor}")

    if isinstance(geo, dict) and "proxy" in geo:
        gproxy = "是" if geo.get("proxy") else "否"
        ghosting = "是" if geo.get("hosting") else "否"
        gmobile = "是" if geo.get("mobile") else "否"
        lines.append(
            f"  • ip\\-api 标记  代理:{gproxy}  托管:{ghosting}  移动:{gmobile}"
        )

    return "\n".join(lines)


# ============================================================
# Telegram 处理逻辑
# ============================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "👋 我是 IP 查询机器人。\n\n"
        "直接发送一个 *IPv4* 或 *IPv6* 地址，我会返回：\n"
        "📍 地理位置 · 🏢 网络运营商 · 🔗 ASN\n"
        "🛰️ BGP 路由 · 📋 RDAP 注册信息 · 🛡️ 风险信号\n\n"
        "示例：`8.8.8.8` 或 `2001:4860:4860::8888`"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN_V2)


async def handle_ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    raw = (update.message.text or "").strip()

    try:
        ip_obj = ipaddress.ip_address(raw)
    except ValueError:
        await update.message.reply_text(
            "❌ 请输入合法的 IPv4 或 IPv6 地址。\n例如：`8.8.8.8`",
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
        await update.message.reply_text(
            "⚠️ 这是私有 / 保留地址，外部数据源无法查询。请换一个公网 IP。",
        )
        return

    ip = str(ip_obj)
    msg = await update.message.reply_text("⏳ 正在查询，请稍候…")

    try:
        data = await query_all(ip)
        result = format_result(ip, data)
    except Exception as e:
        logger.exception("查询 %s 时出错", ip)
        await msg.edit_text(f"❌ 查询出错：{e}")
        return

    if len(result) > 4000:
        result = result[:4000] + "\n… （结果已截断）"

    try:
        await msg.edit_text(result, parse_mode=ParseMode.MARKDOWN_V2)
    except Exception:
        plain = result.replace("*", "").replace("`", "").replace("\\", "")
        await msg.edit_text(plain)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Update 出错", exc_info=context.error)


# ============================================================
# 启动
# ============================================================

def main() -> None:
    if not BOT_TOKEN:
        raise SystemExit("请先设置环境变量 BOT_TOKEN")

    # 启动健康检查 HTTP 服务（给云平台用）
    Thread(target=start_health_server, daemon=True).start()

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_ip)
    )
    app.add_error_handler(error_handler)

    logger.info("机器人已启动，按 Ctrl+C 停止")
    app.run_polling(
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=True,
    )


if __name__ == "__main__":
    main()
