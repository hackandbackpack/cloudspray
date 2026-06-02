"""Realistic HTTP User-Agent strings for request rotation.

CloudSpray rotates User-Agent headers across spray requests to avoid
simple detection rules that flag repeated requests from the same UA.
These strings represent common browsers and Microsoft desktop clients
seen in real corporate environments.

The spray engine and CA probe module select a random UA from this list
for each request. This is not a strong evasion technique on its own,
but it avoids the most basic "same UA from thousands of requests" alerts.

All strings are kept reasonably current (Chrome 120-122, Edge 120-122,
Firefox 121-123, Safari 17.2) to match what real corporate users would
send from up-to-date systems.
"""

USER_AGENTS: list[str] = [
    # Edge on Windows 11
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92",
    # Edge on Windows 10
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91",
    # Chrome on Windows 11
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome on Windows 10
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox on Windows 11
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Firefox on Windows 10
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Safari on macOS Sonoma
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Safari on macOS Ventura
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Outlook desktop client
    "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17328; Pro)",
    # Teams desktop client
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/24004.1307.2669.7070 Chrome/120.0.6099.291 Electron/28.2.7 Safari/537.36",
]
