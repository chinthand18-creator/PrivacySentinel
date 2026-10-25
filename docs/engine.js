/* Privacy Sentinel - URL heuristics (port of host/security_engine.py analyze_url).
   Pure functions, no network. Works in the browser and in Node. */
(function (root) {
  "use strict";
  const OCT = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
  const STRICT_V4 = new RegExp(`^${OCT}(?:\\.${OCT}){3}$`);
  const LEGACY_V4 = /^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$/i;

  // Accepts 127.1, 2130706433, 0x7f.1 ... like inet_aton. Returns 4 octets or null.
  function legacyV4(host) {
    if (!LEGACY_V4.test(host)) return null;
    const nums = [];
    for (const p of host.split(".")) {
      if (/^0x[0-9a-f]+$/i.test(p)) nums.push(parseInt(p, 16));
      else if (/^0[0-7]*$/.test(p)) nums.push(parseInt(p, 8));
      else if (/^[1-9]\d*$/.test(p)) nums.push(parseInt(p, 10));
      else return null;
    }
    const last = nums.pop();
    if (nums.some((n) => n > 255) || last >= Math.pow(256, 4 - nums.length)) return null;
    let value = last;
    nums.forEach((n, i) => { value += n * Math.pow(256, 3 - i); });
    return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
  }

  function isPublicV4([a, b, c]) {
    if ([0, 10, 127].includes(a) || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && (b === 168 || (b === 0 && c <= 2))) return false;
    if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    return true;
  }

  function isPublicIp(ip) {
    if (STRICT_V4.test(ip)) return isPublicV4(ip.split(".").map(Number));
    return !/^\[?(::1?|fe[89ab]|f[cd]|::ffff:|2001:db8)/i.test(ip);
  }

  function parse(raw) {
    const value = (raw || "").trim();
    if (!value) throw new Error("Enter a URL first.");
    const candidate = value.includes("://") ? value : "https://" + value;
    const scheme = candidate.split("://")[0].toLowerCase();
    if (scheme !== "http" && scheme !== "https") throw new Error("Only HTTP and HTTPS URLs are supported.");
    const authority = candidate.slice(scheme.length + 3).split(/[/?#]/)[0];
    if (authority.includes("@")) throw new Error("URLs containing embedded credentials are not accepted.");
    const portText = authority.startsWith("[") ? authority.split("]")[1] : authority.split(":")[1];
    if (portText && !(/^:?\d+$/.test(portText) && +portText.replace(":", "") >= 1 && +portText.replace(":", "") <= 65535)) {
      throw new Error("The URL contains an invalid port.");
    }
    let url;
    try { url = new URL(candidate); } catch (e) { throw new Error("The URL is not valid."); }
    const rawHost = (authority.startsWith("[") ? authority.split("]")[0] + "]" : authority.split(":")[0])
      .replace(/\.$/, "").toLowerCase();
    if (!rawHost) throw new Error("The URL has no valid hostname.");
    const isIp = STRICT_V4.test(rawHost) || rawHost.startsWith("[");
    if (!isIp && !legacyV4(rawHost)) {
      const labels = url.hostname.replace(/\.$/, "").split(".");
      if (rawHost.includes("..") || url.hostname.length > 253 || labels.some((l) => l.length < 1 || l.length > 63)) {
        throw new Error("The hostname is invalid.");
      }
    }
    return { scheme, host: rawHost, ascii: url.hostname.replace(/\.$/, ""), query: url.search.replace(/^\?/, "") };
  }

  function analyzeUrl(raw) {
    let info;
    try { info = parse(raw); } catch (e) {
      return { score: 0, level: "INVALID", findings: [e.message] };
    }
    const { host, scheme } = info;
    const findings = [];
    let score = 0;
    const add = (points, text) => { score += points; findings.push(text); };

    if (scheme === "http") add(25, "The URL uses HTTP rather than HTTPS.");
    const strict = STRICT_V4.test(host), v6 = host.startsWith("[");
    const legacy = !strict && !v6 ? legacyV4(host) : null;
    if (strict || v6 || legacy) {
      add(15, `The hostname is an IP address (IPv${v6 ? 6 : 4}).`);
      if (legacy) add(15, "The IP is written in a non-standard shorthand form that is sometimes used to disguise the destination.");
      const publicIp = legacy ? isPublicV4(legacy) : isPublicIp(host);
      if (!publicIp) add(25, "The IP is not globally routable. Treat this destination carefully.");
    } else if (!host.includes(".")) {
      add(10, "The hostname is not a conventional public domain.");
    }
    if (/[^\x00-\x7f]/.test(host) || host.split(".").some((l) => l.startsWith("xn--"))) {
      add(15, "The hostname contains internationalized characters; check for look-alike characters.");
    }
    if (host.length > 45) add(10, "The hostname is unusually long.");
    if ((host.match(/-/g) || []).length >= 4) add(5, "The hostname contains many hyphens.");
    if (info.query.length > 200) findings.push("The URL has a long query string. Check that it contains no private tokens.");

    score = Math.min(score, 100);
    const level = score >= 40 ? "HIGH" : score >= 20 ? "REVIEW" : "LOW";
    if (!findings.length) findings.push("No configured local warning patterns were detected. This does not prove the website is safe.");
    return { score, level, findings, hostname: info.ascii, scheme };
  }

  const api = { analyzeUrl, isPublicIp };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.SentinelEngine = api;
})(typeof self !== "undefined" ? self : this);
