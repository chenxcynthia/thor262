from http.server import BaseHTTPRequestHandler, HTTPServer
import requests


def response_denied(country: str) -> bytes:
    denied_template = "<html>" \
                      "<head><title>Access Denied</title></head>" \
                      "<body><h1>Unfortunately, you are not allowed to access this website from {country}.</h1></body>" \
                      "</html>"
    if country is None:
        denied = denied_template.format(country="your country")
    else:
        denied = denied_template.format(country=country)
    return bytes(denied, "utf-8")


def response_accepted(country: str) -> bytes:
    accepted_template = "<html>" \
                        "<head><title>Welcome</title></head>" \
                        "<body><h1>Welcome to our nice website, visitor from {country}.</h1></body>" \
                        "</html>"
    if country is None:
        accepted = accepted_template.format(country="your country")
    else:
        accepted = accepted_template.format(country=country)
    return bytes(accepted, "utf-8")


def get_country(ip: str) -> str:
    data = requests.get("https://ipinfo.io/{}/json".format(ip)).json()
    if "country" not in data:
        return None
    else:
        return data["country"]


class Server(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        country = get_country(self.client_address[0])
        if country in ["US", None]:
            response = response_denied(country)
            print("Request received from {} -- denied".format(country))
        else:
            response = response_accepted(country)
            print("Request received from {} -- accepted".format(country))
        self.wfile.write(response)


if __name__ == "__main__":
    server = HTTPServer(('0.0.0.0', 80), Server)
    print("Server started http://%s:%s" % ('0.0.0.0', 80))
    server.serve_forever()
    server.server_close()
