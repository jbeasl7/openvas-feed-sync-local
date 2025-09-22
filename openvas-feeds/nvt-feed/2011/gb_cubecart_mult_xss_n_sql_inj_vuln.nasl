# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cubecart:cubecart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802199");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2010-4903");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-11-04 11:10:29 +0200 (Fri, 04 Nov 2011)");

  script_name("CubeCart Multiple Cross-Site Scripting and SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41352");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43114");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/513572/100/0/threaded");
  script_xref(name:"URL", value:"http://www.acunetix.com/blog/web-security-zone/articles/sql-injection-xss-cubecart-4-3-3/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_cubecart_detect.nasl");
  script_mandatory_keys("cubecart/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site and
  manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"CubeCart version 4.3.3.");

  script_tag(name:"insight", value:"The flaws are due to

  - Input passed to the 'amount', 'cartId', 'email', 'transId', and
    'transStatus' parameters in 'modules/gateway/WorldPay/return.php' is not
    properly sanitised before being returned to the user.

  - Input passed via the 'searchStr' parameter to index.php
    (when '_a' is set to 'viewCat') is not properly sanitised before being used
    in a SQL query.");

  script_tag(name:"solution", value:"Upgrade to CubeCart version 4.4.2 or later.");

  script_tag(name:"summary", value:"CubeCart is prone to SQL injection and multiple cross-site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.cubecart.com/tour");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?searchStr='&_a=viewCat&Submit=Go";

if (http_vuln_check(port:port, url:url, pattern:"You have an error in your SQL syntax;",
                    extra_check:"> SELECT id FROM .*CubeCart_search WHERE searchstr=")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
