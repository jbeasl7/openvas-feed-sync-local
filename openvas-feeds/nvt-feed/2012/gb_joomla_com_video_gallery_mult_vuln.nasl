# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902673");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-04-25 18:38:13 +0530 (Wed, 25 Apr 2012)");

  script_name("Joomla! 'Video Gallery' Component Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://1337day.com/exploits/18125");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/112161/joomlavideogallery-lfisql.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL queries by
injecting arbitrary SQL code and read arbitrary files via directory traversal attacks and gain sensitive
information.");

  script_tag(name:"affected", value:"Joomla! Video Gallery Component");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - Input passed via the 'Itemid' parameter to index.php script is not properly sanitised before being used in SQL
queries.

  - Improper validation of user-supplied input passed via the 'controller' parameter to 'index.php', which allows
attackers to read arbitrary files via ../(dot dot) sequences.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Joomla! Video Gallery component is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

url = dir + "/index.php?option=com_videogallery&Itemid='";

if (http_vuln_check(port: port, url: url, check_header:TRUE, pattern:"You have an error in your SQL syntax;")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: url);
  exit(0);
}

exit(99);
