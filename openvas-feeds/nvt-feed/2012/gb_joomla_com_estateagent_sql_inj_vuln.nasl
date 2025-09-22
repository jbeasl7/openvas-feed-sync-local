# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802745");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2011-4571");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Joomla Estate Agent Component 'id' Parameter SQL Injection Vulnerability");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-12 18:02:44 +0530 (Thu, 12 Apr 2012)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/70444");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52963");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18728/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50024");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/111749/joomlatheestateagent-sql.txt");
  script_xref(name:"URL", value:"http://www.sectechno.com/2012/04/11/sql-injection-in-joomla-com_estateagent/");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL queries by
injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Joomla The Estate Agent Component");

  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'id' parameter to 'index.php' (when
'option' is set to 'com_estateagent') is not properly sanitised before being used in an SQL query.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Joomla The Estate Agent component is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

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

url = dir + "/index.php?option=com_estateagent&Itemid=47&act=object&task=showEO&id='";

if (http_vuln_check(port: port, url: url, extra_check: "[j|J]oomla", check_header:TRUE,
                    pattern: "Invalid argument supplied for foreach\(\)|You have an error in your SQL syntax;")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
