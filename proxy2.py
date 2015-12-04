# -*- coding: utf-8 -*-
import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
from xml.etree.ElementTree import Element,SubElement,ElementTree, parse
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from HTMLParser import HTMLParser
import logging
import logging.handlers

def set_logger(log_file):
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    console.setFormatter(logging.Formatter('[%(asctime)s] %(message)s'))
    hdlr=logging.handlers.RotatingFileHandler(log_file,maxBytes=1048576,backupCount=5)
    hdlr.setFormatter(logging.Formatter('[%(asctime)s] %(message)s'))
    hdlr.setLevel(logging.DEBUG)
    logger.addHandler(hdlr)
    logger.addHandler(console)
    return logger,console


def log_with_color(c, s):
    global console
    global logger
    console.setFormatter(logging.Formatter("[%s]\r\n\x1b[%dm%s\x1b[0m" %  ('%(asctime)s',c, '%(message)s')))
    logger.debug(s)
    console.setFormatter(logging.Formatter('[%(asctime)s] %(message)s'))

def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}
        #self.config = config

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        if self.config["intercept"]=="1" and "sslkey" in self.config:
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = "/cache/certs/%s.crt" % hostname
        with self.lock:
            if not os.path.isfile(certpath):
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.config["sslkey"], "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.config["sslkey"].replace("key","crt"), "-CAkey", self.config["sslkey"], "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.config["sslkey"], certfile=certpath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif (conntype.lower() == 'keep-alive' and self.protocol_version >= "HTTP/1.1"):
            self.close_connection = 0

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        #if self.path == 'http://proxy2.test/':
        #    self.send_cacert()
        #    return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None
        if req.path[0] == '/':
            if "forward" in self.config:
                CHECK_FOR_REJECT=True
                divert=self.config["forward"]["divert"].split(",")
                if "rejectunknownforward" not in self.config["forward"]:
                    self.config["forward"]["rejectunknownforward"] = "1"
                if req.path.lower() =="/"+divert[0] or req.path.lower().startswith("/"+divert[0]+"/"):
                    if "useragent" in self.config["forward"]:
                        user_agent_match = False
                        for user_agent in self.config["forward"]["useragent"].split(","):
                            if user_agent.lower() in self.headers['User-Agent'].lower():
                                user_agent_match = True
                                break
                        if user_agent_match:
                            CHECK_FOR_REJECT=False
                            req.path = "%s%s" % (divert[1],req.path)
                            if "headers" in self.config["forward"]:
                                for header in self.config["forward"]["headers"]:
                                    req.headers[header] = self.config["forward"]["headers"][header]
                if CHECK_FOR_REJECT and self.config["forward"]["rejectunknownforward"] == "1":
                    self.send_error(403)
                    return
            else:
                if isinstance(self.connection, ssl.SSLSocket):
                    req.path = "https://%s%s" % (req.headers['Host'], req.path)
                else:
                    req.path = "http://%s%s" % (req.headers['Host'], req.path)
                    

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, host, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if host:
            req.headers['Host'] = host
        req_headers = self.filter_headers(req.headers)

        try:
            if not host in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[host] = httplib.HTTPSConnection(host, timeout=self.timeout)
                else:
                    self.tls.conns[host] = httplib.HTTPConnection(host, timeout=self.timeout)
            conn = self.tls.conns[host]
            conn.request(self.command, path, req_body, dict(req_headers))
            res = conn.getresponse()
            res_body = res.read()
        except Exception as e:
            if host in self.tls.conns:
                del self.tls.conns[host]
            self.send_error(502)
            return

        version_table = {9: 'HTTP/0.9', 10: 'HTTP/1.0', 11: 'HTTP/1.1'}
        setattr(res, 'headers', res.msg)
        setattr(res, 'response_version', version_table[res.version])

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        res_headers = self.filter_headers(res.headers)

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res_headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    do_HEAD = do_GET
    do_POST = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]
        return headers

    def encode_content_body(self, text, encoding):
        if encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        elif encoding == 'identity':
            data = text
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            text = zlib.decompress(data)
        elif encoding == 'identity':
            text = data
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    # def send_cacert(self):
    #     with open(self.cacert, 'rb') as f:
    #         data = f.read()

    #     self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
    #     self.send_header('Content-Type', 'application/x-x509-ca-cert')
    #     self.send_header('Content-Length', len(data))
    #     self.send_header('Connection', 'close')
    #     self.end_headers()
    #     self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        log_with_color(33, req_header_text)

        u = urlparse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            log_with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % query_text)

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            log_with_color(32, "==== COOKIE ====\n%s\n" % cookie)

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            log_with_color(31, "==== BASIC AUTH ====\n%s\n" % token)

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                log_with_color(32, "==== REQUEST BODY ====\n%s\n" % req_body_text)

        log_with_color(36, res_header_text)

        cookie = res.headers.get('Set-Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            log_with_color(31, "==== SET-COOKIE ====\n%s\n" % cookie)

        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>([\s\S]+?)</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    log_with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                log_with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text)

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        if self.config["verbose"] == "1":
            self.print_info(req, req_body, res, res_body)
        else:
            pass

class SSLProxyRequestHandler(ProxyRequestHandler):
    def __init__(self, *args, **kwargs):
        ProxyRequestHandler.__init__(self, *args, **kwargs)
    

def xml_iterparent(tree):
    for parent in tree.getiterator():
        for child in parent:
            yield parent, child

def parse_config_file(config_file):
    Root =parse(config_file).getroot()
    config_dict={}
    for parent,child in xml_iterparent(Root):
        if parent.tag == "Config":
            if len(child.text.rstrip()) == 0:
                config_dict[child.tag]={}
            else:
                config_dict[child.tag]=child.text.rstrip()
    for parent,child in xml_iterparent(Root):
        if parent.tag in config_dict:
            ### SSLGateWay tag
            if parent.tag == "SSLGateWay":
                config_dict[parent.tag][child.tag]=child.text.rstrip()
                if child.tag == "Forward":
                    if "forward" not in config_dict[parent.tag]:
                        config_dict[parent.tag]["forward"]={}
                    for sub_parent,sub_child in xml_iterparent(child):
                        if sub_child.tag == "headers":
                            if "headers" not in config_dict[parent.tag]["forward"]:
                                config_dict[parent.tag]["forward"]["headers"]={}
                            config_dict[parent.tag]["forward"]["headers"][sub_child.text.rstrip().split(",")[0]]=sub_child.text.rstrip().split(",")[1]
                        else:
                            config_dict[parent.tag]["forward"][sub_child.tag]=sub_child.text.rstrip()
            ### Proxy tag
            if parent.tag == "Proxy":
                config_dict[parent.tag][child.tag]=child.text.rstrip()
    return config_dict

if __name__ == '__main__':
    config=parse_config_file("/etc/proxy/proxy.xml")
    logger,console = set_logger("/var/log/proxy.log")
    
    
    ServerClass=ThreadingHTTPServer
    
    if "SSLGateWay" in config:
        if "sslkey" in config["SSLGateWay"] and "sslport" in config["SSLGateWay"]:
            if "sslport" not in config["SSLGateWay"]:
                config["SSLGateWay"]["sslport"] = "443"
            if "ssladdress" not in config["SSLGateWay"]:
                config["SSLGateWay"]["ssladdress"] = ""
            if "intercept" not in config["SSLGateWay"]:
                config["SSLGateWay"]["intercept"]=="0"
            if "verbose" not in config["SSLGateWay"]:
                config["SSLGateWay"]["verbose"] = "0"
            SSLHandlerClass=SSLProxyRequestHandler
            #(config["SSLGateWay"])
            SSLHandlerClass.protocol_version = "HTTP/1.0"
            
            SSLHandlerClass.config=config["SSLGateWay"]
            ssl_server_address = (config["SSLGateWay"]["ssladdress"], int(config["SSLGateWay"]["sslport"]))
            ssl_httpd = ServerClass(ssl_server_address, SSLHandlerClass)
            ssl_httpd.socket = ssl.wrap_socket(ssl_httpd.socket, keyfile=config["SSLGateWay"]["sslkey"], certfile=config["SSLGateWay"]["sslcert"], server_side=True)
            sa = ssl_httpd.socket.getsockname()
            logger.debug("Serving SSL HTTP Gateway on %s port %s ..." % (sa[0], sa[1]))
            #ssl_httpd.serve_forever()
            threading.Thread(target=ssl_httpd.serve_forever).start()
    if "Proxy" in config:
        if "port" not in config["Proxy"]:
            config["Proxy"]["port"]="8080"
        if "address" not in config["Proxy"]:
            config["Proxy"]["address"]=""
        if "intercept" not in config["Proxy"]:
            config["Proxy"]["intercept"]="0"
        if "verbose" not in config["Proxy"]:
                config["Proxy"]["verbose"] = "0"
        HandlerClass=ProxyRequestHandler#(config["Proxy"])
        HandlerClass.protocol_version = "HTTP/1.1"
        
        HandlerClass.config=config["Proxy"]
        server_address = (config["Proxy"]["address"], int(config["Proxy"]["port"]))
        httpd = ServerClass(server_address, HandlerClass)
        sa = httpd.socket.getsockname()
        logger.debug("Serving HTTP Proxy on %s port %s ..." % (sa[0], sa[1]))
        #httpd.serve_forever()
        threading.Thread(target=httpd.serve_forever).start()
    
    while True:
        try:
            time.sleep(1)
        except:
            ssl_httpd.shutdown()
            httpd.shutdown()
            break
            
            
    
