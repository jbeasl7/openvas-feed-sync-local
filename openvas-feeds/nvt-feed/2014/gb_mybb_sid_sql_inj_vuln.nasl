# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903231");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-02-26 11:23:07 +0530 (Wed, 26 Feb 2014)");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB sid SQLi Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mybb/http/detected");

  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/mybb-1612-sql-injection");

  script_tag(name:"summary", value:"MyBB is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check
  whether it is possible to execute sql query.");

  script_tag(name:"insight", value:"Flaw is due to improper validation of user-supplied input
  passed to 'sid' parameter in 'search.php' page.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code and gain sensitive information.");

  script_tag(name:"affected", value:"MyBB version 1.6.12. Previous versions may also be
  affected.");

  script_tag(name:"solution", value:"Update to version 1.6.13 or later.");

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

url = dir + "/search.php?action=results&sid[0]=9afaea732cb32f06fa34b1888bd237e2&sortby=&order=";

if(http_vuln_check(port:port, url:url, check_header:FALSE, pattern:"expects parameter 2 to be string, array given", extra_check:"db_mysqli.php")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
}

exit(0);
