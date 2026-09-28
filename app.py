import datetime
import socket
import ssl
from urllib.parse import urlparse
import requests
import streamlit as st
from cryptography import x509
from cryptography.hazmat.backends import default_backend

st.set_page_config(
    page_title="Web Security Headers & SSL/TLS Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Web Security Headers & SSL/TLS Analyzer")
st.markdown(
    "Defensive assessment tool evaluating **OWASP Recommended HTTP Security Headers** "
    "and public **SSL/TLS Certificate** parameters."
)

# Diccionario de cabeceras defensivas y su peso en el scoring
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 20,
        "recommendation": "Enforces HTTPS connections and prevents SSL stripping.",
        "snippet": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "weight": 25,
        "recommendation": "Restricts sources of executable scripts, stylesheets, and assets to mitigate XSS.",
        "snippet": "Content-Security-Policy: default-src 'self';"
    },
    "X-Frame-Options": {
        "weight": 15,
        "recommendation": "Mitigates Clickjacking by controlling whether the site can be framed.",
        "snippet": "X-Frame-Options: DENY"
    },
    "X-Content-Type-Options": {
        "weight": 15,
        "recommendation": "Prevents MIME-type sniffing by enforcing declared Content-Type.",
        "snippet": "X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "weight": 15,
        "recommendation": "Controls how much referrer information is transmitted with requests.",
        "snippet": "Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "weight": 10,
        "recommendation": "Controls access to browser features and APIs (camera, microphone, geolocation).",
        "snippet": "Permissions-Policy: camera=(), microphone=(), geolocation=()"
    }
}

def analyze_headers(target_url):
    try:
        response = requests.get(target_url, timeout=10, allow_redirects=True)
        headers = response.headers
        findings = []
        earned_score = 0

        for header_name, meta in SECURITY_HEADERS.items():
            if header_name in headers:
                findings.append({
                    "header": header_name,
                    "status": "Present",
                    "value": headers[header_name],
                    "recommendation": meta["recommendation"],
                    "snippet": meta["snippet"],
                    "weight": meta["weight"]
                })
                earned_score += meta["weight"]
            else:
                findings.append({
                    "header": header_name,
                    "status": "Missing",
                    "value": None,
                    "recommendation": meta["recommendation"],
                    "snippet": meta["snippet"],
                    "weight": meta["weight"]
                })
        return earned_score, findings, None
    except requests.exceptions.RequestException as e:
        return 0, [], str(e)

def inspect_tls_certificate(hostname, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                tls_version = ssock.version()

        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
        not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
        
        now = datetime.datetime.now(datetime.timezone.utc) if hasattr(cert, 'not_valid_after_utc') else datetime.datetime.utcnow()
        days_left = (not_after - now).days

        return {
            "tls_version": tls_version,
            "cipher": cipher[0] if cipher else "Unknown",
            "issuer": cert.issuer.rfc4514_string(),
            "valid_from": not_before.strftime("%Y-%m-%d"),
            "valid_to": not_after.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "expired": days_left < 0
        }, None
    except Exception as e:
        return None, str(e)

# Formulario de entrada
with st.form("scan_form"):
    target_input = st.text_input(
        "Enter Target URL",
        placeholder="https://example.com",
        help="Include http:// or https://"
    )
    submitted = st.form_submit_button("🔍 Run Defensive Audit")

if submitted and target_input:
    # Normalización de URL
    raw_url = target_input.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    
    parsed = urlparse(raw_url)
    hostname = parsed.hostname

    if not hostname:
        st.error("Invalid URL format. Please provide a valid hostname.")
    else:
        st.subheader(f"Audit Results for: `{raw_url}`")
        score, findings, header_err = analyze_headers(raw_url)

        if header_err:
            st.error(f"Error fetching HTTP response: {header_err}")
        else:
            # Calificación
            col1, col2, col3 = st.columns(3)
            col1.metric("Security Posture Score", f"{score} / 100")

            grade = "A" if score >= 85 else ("B" if score >= 65 else ("C" if score >= 40 else "F"))
            col2.metric("Rating", grade)

            missing_count = sum(1 for f in findings if f["status"] == "Missing")
            col3.metric("Missing Critical Headers", missing_count)

            # Tablas y detalles
            st.markdown("### HTTP Security Headers Inspection")
            for item in findings:
                if item["status"] == "Present":
                    with st.expander(f"✅ {item['header']} (Present)", expanded=False):
                        st.code(item["value"], language="text")
                        st.caption(item["recommendation"])
                else:
                    with st.expander(f"❌ {item['header']} (Missing)", expanded=True):
                        st.warning(item["recommendation"])
                        st.markdown("**Remediation Snippet:**")
                        st.code(item["snippet"], language="nginx")

        # Auditoría TLS si es HTTPS
        if parsed.scheme == "https":
            st.markdown("---")
            st.markdown("### SSL/TLS Certificate Telemetry")
            cert_data, cert_err = inspect_tls_certificate(hostname)

            if cert_err:
                st.warning(f"Unable to establish TLS handshake inspection: {cert_err}")
            else:
                c1, c2, c3 = st.columns(3)
                c1.metric("TLS Protocol", cert_data["tls_version"])
                c2.metric("Validity Status", "Valid" if not cert_data["expired"] else "Expired")
                c3.metric("Days Until Expiration", f"{cert_data['days_left']} days")

                st.json({
                    "Issuer": cert_data["issuer"],
                    "Cipher Suite": cert_data["cipher"],
                    "Valid From": cert_data["valid_from"],
                    "Valid Until": cert_data["valid_to"]
                })