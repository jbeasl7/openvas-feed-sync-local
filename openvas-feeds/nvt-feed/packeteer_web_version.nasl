# SPDX-FileCopyrightText: 2008 nnposter
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80033");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Packeteer Web Management Interface Version Detection (HTTP)");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 nnposter");
  script_dependencies("packeteer_web_login.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("bluecoat_packetshaper/installed");

  script_tag(name:"summary", value:"HTTP based detection of the Packeteer Web Management
  Interface version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

# Notes:
# - Info page is bigger than 8K and PacketShaper does not use Content-Length.
#   The script uses custom http_send_recv_length() to retrieve the entire page.

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

if(!get_kb_item("bluecoat_packetshaper/installed"))
  exit(0);

function set_cookie(data, cookie) {
  local_var EOL, req;

  EOL = '\r\n';
  req = ereg_replace(string:data, pattern:EOL + 'Cookie:[^\r\n]+', replace:"");
  req = ereg_replace(string:req, pattern:EOL + EOL, replace:EOL + cookie + EOL);
  return req;
}

function http_send_recv_length(port, data, length) {
  local_var sock, resp;

  sock = http_open_socket(port);
  if(!sock)
    return;

  send(socket:sock, data:data);
  resp = http_recv_length(socket:sock, bodylength:length);
  http_close_socket(sock);
  return resp;
}

function get_version(port, cookie) {
  local_var req, resp, match;

  if(!port || !cookie)
    return;

  if(!get_tcp_port_state(port))
    return;

  req = set_cookie(data:http_get(item:"/info.htm", port:port), cookie:cookie);
  resp = http_send_recv_length(port:port, data:req, length:64000);
  if(!resp)
    return;

  match = eregmatch(pattern:'makeState\\("Software(.nbsp.| )Version:", *"([0-9A-Za-z.]+)', string:resp);
  return match[2];
}

port = http_get_port(default:80);
product = get_kb_item("www/" + port + "/packeteer");
if(!product)
  exit(0);

if(!cookie = get_kb_item("/tmp/http/auth/" + port))
  exit(0);

version = get_version(port:port, cookie:cookie);
if(!version)
  exit(0);

replace_kb_item(name:"www/" + port + "/packeteer/version", value:version);
report = string("Packeteer " + product + " web interface version is " + version);
log_message(port:port, data:report);

exit(0);