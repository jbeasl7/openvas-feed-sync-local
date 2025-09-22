# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103791");
  script_version("2024-11-19T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-11-19 05:05:41 +0000 (Tue, 19 Nov 2024)");
  script_tag(name:"creation_date", value:"2013-09-19 18:42:42 +0200 (Thu, 19 Sep 2013)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Multiple Trendnet Camera Products Security Bypass Vulnerability (Jan 2012) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("netcam/banner");

  script_tag(name:"summary", value:"Multiple Trendnet Camera products are prone to a remote
  security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if it is possible to access /anony/mjpg.cgi without
  authentication.");

  script_tag(name:"insight", value:"On vulnerable devices it is possible to access the livestream
  without any authentication by requesting http://example.com/anony/mjpg.cgi.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow remote attackers
  to gain access to a live stream from the camera.");

  script_tag(name:"affected", value:"TV-VS1P V1.0R 0, TV-VS1 1.0R 0, TV-IP422WN V1.0R 0,
  TV-IP422W A1.0R 0, TV-IP422 A1.0R 0, TV-IP410WN 1.0R 0, TV-IP410W A1.0R 0, TV-IP410 A1.0R 0,
  TV-IP322P 1.0R 0, TV-IP312WN 1.0R 0, TV-IP312W A1.0R 0, TV-IP312 A1.0R 0, TV-IP252P B1.xR 0,
  TV-IP212W A1.0R 0, TV-IP212 A1.0R 0, TV-IP121WN v2.0R 0, TV-IP121WN 1.0R 0, TV-IP121W A1.0R 0,
  TV-IP110WN 2.0R 0, TV-IP110WN 1.0R, TV-IP110W A1.0R 0, TV-IP110 A1.0R 0.");

  script_tag(name:"solution", value:"Vendor updates are available.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51922");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/36680");
  script_xref(name:"URL", value:"http://www.trendnet.com/press/view.asp?id=1959");
  script_xref(name:"URL", value:"http://www.trendnet.com/products/proddetail.asp?prod=145_TV-IP110W");
  script_xref(name:"URL", value:"http://console-cowboys.blogspot.com.au/2012/01/trendnet-cameras-i-always-feel-like.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if ("401 Unauthorized" >!< banner || 'Basic realm="netcam"' >!< banner)
  exit(0);

url = "/anony/mjpg.cgi";

req = 'GET ' + url + ' HTTP/1.0\r\n\r\n';
res = http_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && "x-mixed-replace" >< res && "image/jpeg" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
