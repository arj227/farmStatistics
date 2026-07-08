import http.server
import ssl
import urllib.parse
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ALLOWED_MACS = ["ACA704E74E3C"]

with open("ca.key", "rb") as f:
    CA_KEY = serialization.load_pem_private_key(f.read(), password=None)
with open("ca.crt", "rb") as f:
    CA_CERT = x509.load_pem_x509_certificate(f.read())


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path != "/enroll":
            self.send_error(404)
            return

        mac = params.get("mac", [None])[0]
        if not mac or mac.upper() not in ALLOWED_MACS:
            self.send_error(403, "MAC not authorized")
            return

        try:
            device_key = ec.generate_private_key(ec.SECP256R1(), default_backend)

            cert = (
                x509.CertificateBuilder()
                .subject_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, mac.upper())])
                )
                .issuer_name(CA_CERT.subject)
                .public_key(device_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
                .sign(CA_KEY, hashes.SHA256())
            )

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = device_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )

            body = cert_pem + key_pem
        except Exception as e:
            print(f"enrollment failed for {mac}: {e}")
            self.send_error(500)
            return

        print(f"enrolled {mac}")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        cert = self.connection.getpeercert()
        if not cert:
            self.send_error(401, "No client certificate")
            return False
        subject = dict(x[0] for x in cert.get("subject", []))
        mac = subject.get("commonName", "")
        if mac.upper() not in ALLOWED_MACS:
            self.send_error(401, "MAC not authorized")
            return False
        return True

    def do_GET(self):
        if not self._authorized():
            return

        cert_der = self.connection.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_der)
        mac = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.upper()

        safe_path = os.path.normpath(self.path.lstrip("/"))
        if safe_path.startswith(".."):
            self.send_error(403)
            return

        self.path = f"/{mac}/{safe_path}"
        
        print(f"serving: {self.path}")
        super().do_GET()


httpd = http.server.HTTPServer(("0.0.0.0", 8443), Handler)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("server.crt", "server.key")
ctx.load_verify_locations("ca.crt")
ctx.verify_mode = (
    ssl.CERT_OPTIONAL
)  # optional so /enroll works before device has a cert

httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

print("Serving on https://0.0.0.0:8443")
httpd.serve_forever()
