# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804760");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-08-27 15:58:01 +0530 (Wed, 27 Aug 2014)");
  script_name("Joomla! Spider video player Component SQL Injection Vulnerability");

  script_tag(name:"summary", value:"Joomla! Spider video player Component is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to
execute sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to the /component/spidervideoplayer/index.php script not
properly sanitizing user-supplied input to the 'theme' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
and script code and SQL statements on the vulnerable system, which may leads to access or modify data in the
underlying database.");

  script_tag(name:"affected", value:"Joomla! Spider video player Component version 2.8.3, Other versions may
also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128007");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

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

url = dir + "/component/spidervideoplayer/?view=settings&format=row&"
          + "typeselect=0&playlist=1,&theme='SQL-Injection-Test" ;

if (http_vuln_check(port:http_port, url:url, check_header:FALSE,
                    pattern:"You have an error in your SQL syntax.*SQL-Injection-Test")) {
  report = http_report_vuln_url(port: http_port, url: url);
  security_message(port: http_port, data: report);
  exit(0);
}

exit(0);
