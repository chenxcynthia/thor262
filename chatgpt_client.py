import socket
import ssl
import sys
import json
from client_restructured import *
from tor_protocol import *

request_body_template = '{{"model": "gpt-3.5-turbo", "messages": [{{"role": "user", "content": "{question}"}}], "temperature": 0.7}}'
request_hdr_template = 'POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: {content_len}\r\nAuthorization: Bearer {api_key}\r\n\r\n'


def get_request(api_key: str, gpt_question: str) -> bytes:
    request_body = bytes(request_body_template.format(
        question=gpt_question), 'utf-8')
    request_hdr = bytes(request_hdr_template.format(
        content_len=len(request_body), api_key=api_key), 'utf-8')
    return request_hdr + request_body


def main(argv):
    hostname = "api.openai.com"
    port = 443
    if len(argv) != 2 and len(argv) != 3:
        print("usage: python3 %s <API KEY> [USE TOR]" % argv[0])
        return 1
    with open(argv[1], "r") as api_key_file:
        api_key = api_key_file.read().splitlines()[0]
    gpt_question = input("Enter a question for ChatGPT: ")
    request = get_request(api_key, gpt_question)
    if len(argv) == 2:
        new_sock = ssl.create_default_context().wrap_socket(socket.socket(
            socket.AF_INET, socket.SOCK_STREAM), server_hostname=hostname)
        new_sock.settimeout(4)
        new_sock.connect((hostname, port))
        print("Successfullly connected to %s:%d" % (hostname, port))
        send_all(new_sock, request)
        response = recv_all(new_sock, 1073741824)
    else:
        client = TorClient()
        ip_addr = ['127.0.0.1', '127.0.0.2', '127.0.0.3']
        print('')
        for i in range(3):
            sk = client.create_onion_router(ip_addr[i])
            client.receive_created(sk)
        client.begin(hostname, port)
        if (client.receive_connected()):
            print("Successfullly connected to %s:%d" % (hostname, port))
        else:
            print("Connection to %s:%d failed" % (hostname, port))
            return 0
        client.send_data(request)
        response = client.recv_data()
        client.destroy()
    response = str(response, 'utf-8')
    response = json.loads(response[response.find('\r\n\r\n') + 4:])
    print('')
    if "choices" in response:
        print("ChatGPT says:", response["choices"][0]["message"]["content"])
    else:
        print("Could not get an answer from ChatGPT:",
              response["error"]["message"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
