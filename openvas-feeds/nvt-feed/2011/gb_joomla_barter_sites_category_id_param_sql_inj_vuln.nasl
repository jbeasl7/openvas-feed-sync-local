# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802268");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2011-4829", "CVE-2011-4830");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-11-04 12:12:12 +0530 (Fri, 04 Nov 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! Barter Sites 'com_listing' Component 'category_id' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46368");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50021");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18046");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/105626/joomlabarter-sqlxss.txt");

  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause SQL Injection attack and
gain sensitive information.");

  script_tag(name:"affected", value:"Joomla! Barter Sites Component Version 1.3");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via the
'category_id' parameter to index.php (when 'option' is set to 'com_listing' and 'task' is set to 'browse'), which
allows attacker to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Update to version 1.3.2 or later");

  script_tag(name:"summary", value:"Joomla! Barter Sites component is prone to an SQL injection (SQLi) vulnerability.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?option=com_listing&task=browse&category_id=1'";

if (http_vuln_check(port:port, url:url, check_header: TRUE, pattern:"Invalid argument supplied for foreach\(\)",
                    extra_check:">Warning<")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
