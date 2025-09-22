# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clipbucket_project:clipbucket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804543");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2012-6642", "CVE-2012-6643", "CVE-2012-6644");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-18 12:23:11 +0530 (Fri, 18 Apr 2014)");
  script_name("ClipBucket Multiple Vulnerabilities");

  script_tag(name:"summary", value:"ClipBucket is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to execute
  sql query or not.");

  script_tag(name:"insight", value:"Input passed via multiple parameters to multiple scripts is not properly
  sanitised before being returned to the user. Please see the references for more information.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or
  script code and manipulate SQL queries in the backend database allowing
  for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"ClipBucket version 2.6, Other versions may also be affected.");

  script_tag(name:"solution", value:"Apply the patch from the referenced link.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47474");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108489");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_clipbucket_detect.nasl");
  script_mandatory_keys("clipbucket/Installed");
  script_require_ports("Services/www", 80);
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

if( dir == "/" ) dir = "";

url = dir + "/videos.php?cat=all&seo_cat_name=&sort=most_recent&time=1%27SQL-Injection-Test";

## Extra check is not possible
if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                   pattern:"You have an error in your SQL syntax.*SQL-Injection-Test"))
{
  report = http_report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}
exit(99);
