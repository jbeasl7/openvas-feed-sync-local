# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:invision_power_services:invision_power_board";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12648");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SQL Disclosure in Invision Power Board");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("invision_power_board/installed");
  script_tag(name:"solution", value:"Upgrade to the newest version of this software.");
  script_tag(name:"summary", value:"There is a vulnerability in the current version of Invision Power Board
that allows an attacker to reveal the SQL queries used by the product, and
any page that was built by the administrator using the IPB's interface,
simply by appending the variable 'debug' to the request.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_app_port(cpe:CPE);
if (! port) exit(0);

if(!path = get_app_location(cpe:CPE, port:port))exit(0);

req = http_get(item:string(path, "/?debug=whatever"), port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);

find = string("SQL Debugger");
find2 = string("Total SQL Time");
find3 = string("mySQL time");

if (find >< res || find2 ><  res || find3 >< res )
{
 security_message(port);
 exit(0);
}