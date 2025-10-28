import re
import sys
import ipaddress
import math
from collections import Counter
from datetime import datetime
from typing import List, Dict
import whois           
import dns.resolver    

try:
    from zoneinfo import ZoneInfo
    _PR_TZ = ZoneInfo("America/Puerto_Rico")
except Exception:
    _PR_TZ = None

verbose = True
_cache_ns: Dict[str, List[str]] = {} 
_cache_xns: List[str] = None          
DOMAIN_REGEX = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)\.[a-z]{2,63}$")

def log(msg: str, indent: int = 2):
    #Imprime informacion mas detallada si verbose es True
    if not verbose:
        return
    print(" " * indent + str(msg))

def normalize_domain(s: str) -> str:
    #Normaliza Dominio 
    return s.strip().lower()

def load_ns(domain: str) -> List[str]:
    """
    Obtiene los NS desde DNS y cachea el resultado.
    Retorna lista de NS sin punto final y en minúsculas.
    """
    global _cache_ns
    domain = normalize_domain(domain)
    if domain not in _cache_ns:
        try:
            answers = dns.resolver.resolve(domain, "NS")  # consulta NS
            ns_list = [str(r.target).rstrip(".").lower() for r in answers]
            _cache_ns[domain] = ns_list
        except Exception as e:
            log(f"[DNS NS ERROR] {e}")
            _cache_ns[domain] = []
    return _cache_ns[domain]

def load_xns() -> List[str]:
    """Devuelve nameservers externos"""
    global _cache_xns
    if _cache_xns is None:
        _cache_xns = ["8.8.8.8", "1.1.1.1"]
    return _cache_xns

def _ns_to_ips(ns: str) -> List[str]:
    """
    Dado un nameserver:
    - si ns ya es IP retorna [ns].
    - si ns es FQDN hace lookup A y retorna las IPs encontradas.
    """
    try:
        ipaddress.ip_address(ns)    # valida si es IP
        return [ns]
    except ValueError:
        pass

    try:
        answers = dns.resolver.resolve(ns, "A", lifetime=5)
        return [str(r.address) for r in answers]
    except Exception as e:
        log(f"_ns_to_ips: cannot resolve NS {ns}: {e}")
        return []

def _resolve_with_ns(domain: str, record_type: str, ns_ip: str, lifetime: int = 5):
    """
    Realiza una consulta DNS de tipo record_type usando un resolver apuntando a ns_ip.
    Retorna el objeto de respuesta de dnspython. Lanza excepcion si falla.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ns_ip]
    return resolver.resolve(domain, record_type, lifetime=lifetime)

def ck_name(s: str) -> bool:
    """Verifica el formato del dominio con DOMAIN_REGEX. Retorna True/False."""
    domain = normalize_domain(s)
    if DOMAIN_REGEX.fullmatch(domain) is None:
        log("ck_name: failed regex match")
        return False
    return True

def ck_whois(s: str) -> (bool, Dict[str, object]):
    """
    Consulta WHOIS y devuelve (ok, info) donde info contiene:
      - whois_ns: lista de nameservers desde WHOIS
      - dns_ns: lista de nameservers desde DNS
      - expires: fecha de expiracion (datetime o None)
    No imprime nada aquí
    """
    info = {"whois_ns": [], "dns_ns": [], "expires": None}
    try:
        domain = normalize_domain(s)
        w = whois.whois(domain)
        if not w:
            log("ck_whois: no whois record")
            return False, info

        raw_ns = getattr(w, "name_servers", []) or []
        if isinstance(raw_ns, str):
            whois_ns = [raw_ns.strip(".").lower()]
        else:
            whois_ns = [ns.strip(".").lower() for ns in raw_ns if ns]
        info["whois_ns"] = sorted(set(whois_ns))

        dns_ns = [ns.lower().strip(".") for ns in load_ns(domain)]
        info["dns_ns"] = sorted(set(dns_ns))

        exp = getattr(w, "expiration_date", None)
        if isinstance(exp, list):
            exp = exp[0] if exp else None

        exp_dt = None
        if exp:
            if isinstance(exp, str):
                try:
                    exp_dt = datetime.fromisoformat(exp)
                except Exception:
                    exp_dt = None
            elif isinstance(exp, datetime):
                exp_dt = exp
        info["expires"] = exp_dt

        # Validaciones
        if not whois_ns:
            log("ck_whois: no nameservers in whois")
            return False, info

        if not set(whois_ns).issubset(set(dns_ns)):
            log("ck_whois: different nameservers in whois and DNS")
            return False, info

        if exp_dt:
            days_left = (exp_dt - datetime.now()).days
            if days_left <= 30:
                log("ck_whois: domain close to expiration")
                return False, info

        return True, info
    except Exception as e:
        log(f"ck_whois: exception {e}")
        return False, info

def ck_soa(domain: str) -> (bool, Dict[str, object]):
    """
    Consulta SOA y A desde cada NS (incluye XNS).
    Devuelve (ok, info) con:
      - details: lista
      - soa_serials: lista de seriales encontrados
      - a_ips: lista de IPs A encontrados
    """
    info = {"details": [], "soa_serials": [], "a_ips": []}
    try:
        dns_ns = load_ns(domain)
        xns = load_xns()
        for ns in dns_ns + xns:
            ips = _ns_to_ips(ns)
            for ip in ips:
                # SOA
                try:
                    soa_ans = _resolve_with_ns(domain, "SOA", ip, lifetime=5)
                    soa = soa_ans[0]
                    serial = getattr(soa, "serial", None)
                    if serial is None:
                        serial = str(soa)
                    info["soa_serials"].append(str(serial))
                    info["details"].append((ns, ip, "SOA", str(serial)))
                except Exception as e:
                    info["details"].append((ns, ip, "SOA_ERROR", str(e)))
                # A records
                try:
                    a_ans = _resolve_with_ns(domain, "A", ip, lifetime=5)
                    for r in a_ans:
                        a_addr = getattr(r, "address", None)
                        info["a_ips"].append(str(a_addr or r))
                    info["details"].append((ns, ip, "A_OK", None))
                except Exception as e:
                    info["details"].append((ns, ip, "A_ERROR", str(e)))

        # Validaciones: serial unico y A IPs consistentes
        if info["soa_serials"] and len(set(info["soa_serials"])) > 1:
            log("ck_soa: different SOA serial numbers in DNS")
            return False, info

        if info["a_ips"] and len(set(info["a_ips"])) > 1:
            log("ck_soa: different IP for A record in DNS")
            return False, info

        return True, info
    except Exception as e:
        log(f"ck_soa: exception {e}")
        return False, info

def ck_mx(domain: str) -> (bool, Dict[str, object]):
    """
    Consulta MX y TXT en cada servidor (dns_ns + xns).
    Logica:
      - mx_per_server: lista de sets con los MX devueltos por cada servidor
      - consensus: conjunto de MX que aparecen en >= ceil(total_servers/3)
      - Requiere que servidores_with_consensus >= ceil(total_servers/2)
      - SPF obligatorio; DMARC obligatorio (error si falta)
    Devuelve (ok, info) y no imprime.
    """
    info = {"mx_per_server": [], "consensus": set(), "txts": [], "error": None}
    try:
        dns_ns = load_ns(domain)
        xns = load_xns()
        mx_records = []
        txt_records = []

        servers = dns_ns + xns
        for ns in servers:
            ips = _ns_to_ips(ns)
            for ip in ips:
                mx_set = set()
                # hasta 2 intentos por servidor para tolerar timeouts parciales
                for attempt in range(2):
                    try:
                        mx_ans = _resolve_with_ns(domain, "MX", ip, lifetime=5)
                        mx_list = [str(r.exchange).rstrip(".").lower() for r in mx_ans]
                        mx_set = set(mx_list)
                        mx_records.append(mx_set)
                        break
                    except Exception as e:
                        log(f"ck_mx: attempt {attempt+1} no MX from {ns}({ip}): {e}")
                # recoge TXT (SPF/DMARC)
                try:
                    txt_ans = _resolve_with_ns(domain, "TXT", ip, lifetime=5)
                    txts = []
                    for r in txt_ans:
                        try:
                            txt_val = b"".join(r.strings).decode("utf-8", errors="ignore")
                        except Exception:
                            txt_val = str(r)
                        txts.append(txt_val)
                    txt_records.append(tuple(txts))
                except Exception as e:
                    log(f"ck_mx: no TXT from {ns}({ip}): {e}")

        info["mx_per_server"] = mx_records
        if not mx_records:
            info["error"] = "no_mx"
            return False, info

        # cuenta la aparicion de cada MX entre las respuestas
        counter = Counter()
        for s in mx_records:
            for mx in s:
                counter[mx] += 1

        total_servers = len(mx_records)
        threshold = max(1, math.ceil(total_servers / 3))
        consensus_set = {mx for mx, cnt in counter.items() if cnt >= threshold}
        info["consensus"] = consensus_set
        info["txts"] = [t for rec in txt_records for t in rec]

        if not consensus_set:
            info["error"] = "no_consensus"
            return False, info

        servers_with_consensus = sum(1 for s in mx_records if s & consensus_set)
        servers_needed = math.ceil(total_servers / 2)
        if servers_with_consensus < servers_needed:
            info["error"] = "too_few_servers_with_consensus"
            return False, info

        if not any("v=spf" in t.lower() for t in info["txts"]):
            info["error"] = "no_spf"
            return False, info

        if not any("v=dmarc" in t.lower() for t in info["txts"]):
            info["error"] = "no_dmarc"
            return False, info

        return True, info
    except Exception as e:
        info["error"] = f"exception:{e}"
        return False, info

_failure_label = {
    "name": "bad_ck_name",
    "whois": "bad_ck_whois",
    "soa": "bad_ck_soa",
    "mx": "bad_ck_mx",
}

def run_checks(domain: str) -> bool:
    """
    Ejecuta las comprobaciones y presenta la salida:
    - Muestra secciones completas si verbose == True.
    - Siempre imprime errores criticos de MX (aunque verbose == False).
    """
    domain = normalize_domain(domain)
    now = datetime.now(_PR_TZ) if _PR_TZ else datetime.now()
    timestamp = now.strftime('%m/%d/%Y %I:%M%p')

    if verbose:
        print("\n" + "=" * 60)
        print(f"DNS Check: {domain}")
        print(f"Using ckdns.py  {timestamp}")
        print("-" * 60)

    # Validacion de formato de dominio
    if verbose:
        print("Domain name:")
        print(f"  - {domain}")
    if not ck_name(domain):
        print(f"{domain},{_failure_label['name']}")
        return False

    # WHOIS
    ok, whois_info = ck_whois(domain)
    if verbose:
        print("\nWHOIS:")
        if whois_info.get("whois_ns"):
            print("  - WHOIS NS:")
            for ns in whois_info["whois_ns"]:
                print(f"    - {ns}")
        else:
            print("  - WHOIS NS: None listed")

        if whois_info.get("dns_ns"):
            print("  - DNS NS:")
            for ns in whois_info["dns_ns"]:
                print(f"    - {ns}")
        else:
            print("  - DNS NS: None listed")

        exp_dt = whois_info.get("expires")
        if exp_dt:
            days_left = (exp_dt - datetime.now()).days
            print(f"  - Expires: {exp_dt.strftime('%m/%d/%Y')} ({days_left}d)")
        else:
            print("  - Expires: Unknown")
    if not ok:
        print(f"{domain},{_failure_label['whois']}")
        return False

    # SOA / A
    ok, soa_info = ck_soa(domain)
    if verbose:
        print("\nSOA / A:")
        if soa_info.get("details"):
            for ns in sorted(set(d[0] for d in soa_info["details"])):
                entries = [d for d in soa_info["details"] if d[0] == ns]
                for e in entries:
                    tag = e[2]
                    if tag == "SOA":
                        print(f"  - {ns} ({e[1]}): SOA serial {e[3]}")
                    elif tag == "SOA_ERROR":
                        print(f"  - {ns} ({e[1]}): SOA error: {e[3]}")
                    elif tag == "A_OK":
                        print(f"  - {ns} ({e[1]}): A record returned")
                    elif tag == "A_ERROR":
                        print(f"  - {ns} ({e[1]}): A error: {e[3]}")
        if soa_info.get("soa_serials"):
            print("  SOA serials found:")
            for s in sorted(set(soa_info["soa_serials"])):
                print(f"    - {s}")
        if soa_info.get("a_ips"):
            print("  A record IPs found:")
            for ip in sorted(set(soa_info["a_ips"])):
                print(f"    - {ip}")
    if not ok:
        print(f"{domain},{_failure_label['soa']}")
        return False

    # MX
    ok, mx_info = ck_mx(domain)
    if verbose:
        print("\nMX:")
        if mx_info.get("consensus"):
            for mx in sorted(mx_info["consensus"]):
                print(f"  - MX consensus: {mx}")
        else:
            if mx_info.get("mx_per_server"):
                for i, s in enumerate(mx_info["mx_per_server"], 1):
                    print(f"  - server {i}: {', '.join(sorted(s)) if s else '(no reply)'}")
            else:
                print("  - No MX info")

    # Reporte siempre visible de errores MX
    if not ok:
        err = mx_info.get("error", "unknown_mx_error")
        if err == "no_mx":
            print(f"ck_mx: no MX record for {domain}")
        elif err == "no_consensus":
            print(f"ck_mx: no consensus MX across servers for {domain}")
        elif err == "too_few_servers_with_consensus":
            print(f"ck_mx: too few servers report consensus MX for {domain}")
        elif err == "no_spf":
            print(f"ck_mx: no SPF record for {domain}")
        elif err == "no_dmarc":
            print(f"ck_mx: no DMARC record for {domain}")
        else:
            print(f"ck_mx: error for {domain}: {err}")
        print(f"{domain},{_failure_label['mx']}")
        return False

    print(f"{domain},ok")
    return True

if __name__ == "__main__":
    if not sys.stdin.isatty():
        for line in sys.stdin:
            domain = line.strip()
            if domain:
                run_checks(domain)
    else:
        try:
            while True:
                domain = input("Domain: ").strip()
                if not domain:
                    break
                run_checks(domain)
        except (EOFError, KeyboardInterrupt):
            pass