# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:loxone:miniserver_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107045");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Loxone Smart Home Default Admin Login (HTTP)");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive
  information that may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials admin:admin.");

  script_tag(name:"solution", value:"Change the username and password.");

  script_tag(name:"summary", value:"The remote Loxone installation has default credentials set.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2016-09-07 13:18:59 +0200 (Wed, 07 Sep 2016)");
  script_xref(name:"URL", value:"https://osvdb.info/OSVDB-98155");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_loxone_miniserver_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("loxone/miniserver/detected");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

function newHandshakekey() {
  rand = rand_str(length:16, charset:"0123456789");
  return base64(str:rand);
}

username = "admin";
password = "admin";

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);
rand = rand_str(length:17, charset: "0123456789");
req = string("GET /jdev/sys/getkey?0.", rand, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Accept-Encoding: identity\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "\r\n");
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(res !~ "HTTP/1\.[01] 200" || '{"LL": {' >!< res)
  exit(0);

json_key = eregmatch(pattern:'"LL": [{] "control": "dev/sys/getkey", "value": "([A-F0-9]+)", "Code": "200"}}', string:res, icase:TRUE);
if(!json_key[1])
  exit(0);

key = json_key[1];
passphrase = username + ":" + password;
key = hex2str(key);
protocol = HMAC_SHA1(data:passphrase, key:key);
protocol1 = hexstr(protocol);
websockey_key = newHandshakekey();

req2 = string("GET /ws HTTP/1.1", "\r\n",
              "Host: ", host, "\r\n",
              "User-Agent: ", useragent, "\r\n",
              "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
              "Accept-Language: en-US,en;q=0.5\r\n",
              "Accept-Encoding: identity\r\n",
              "Sec-WebSocket-Version: 13\r\n",
              "origin: http://", host, "\r\n",
              "Sec-WebSocket-Protocol: ", protocol1, "\r\n",
              "Sec-WebSocket-Extensions: permessage-deflate\r\n",
              "Sec-WebSocket-Key: ", websockey_key, "\r\n",
              "Connection: keep-alive, Upgrade\r\n",
              "Pragma: no-cache\r\n",
              "Cache-Control: no-cache\r\n",
              "Upgrade: websocket\r\n",
              "\r\n");
res2 = http_keepalive_send_recv(port:port, data:req2);

if(res2 =~ "^HTTP/1\.[01] 101" && "Sec-WebSocket-Accept" >< res2) {
  report = "It was possible to login into Loxone web interface using username `admin` and password `admin`.";
  security_message(port:port, data: report);
  exit(0);
}

exit(99);
