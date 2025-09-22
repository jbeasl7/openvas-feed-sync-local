# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801829");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_cve_id("CVE-2010-4166", "CVE-2010-4696");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! Multiple SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42133");
  script_xref(name:"URL", value:"http://yehg.net/lab/pr0js/advisories/joomla/core/1.5.21/sql_injection/sqli_(filter_order_Dir)_front.jpg");
  script_xref(name:"URL", value:"http://yehg.net/lab/pr0js/advisories/joomla/core/1.5.21/sql_injection/sqli_(filter_order_Dir)_front.jpg");
  script_xref(name:"URL", value:"http://yehg.net/lab/pr0js/advisories/joomla/core/1.5.21/sql_injection/sqli_(filter_order_Dir)_front.jpg");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause SQL Injection attack and
gain sensitive information.");

  script_tag(name:"affected", value:"Joomla! versions 1.5.x before 1.5.22");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input via the
'filter_order' and 'filter_order_Dir' parameters to 'index.php', which allows attacker to manipulate SQL queries
by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Upgrade to Joomla! 1.5.22 or later.");

  script_tag(name:"summary", value:"Joomla! is prone to multiple SQL injection vulnerabilities.");

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

url = dir + "/index.php?option=com_weblinks&view=category&id=2:joomla" +
             "-specific-links&limit=10&filter_order_Dir=&filter_order=%00";

if (http_vuln_check(port:port, url:url,
                    pattern:'mysql_num_rows(): supplied argument is not a valid MySQL result resource',
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
