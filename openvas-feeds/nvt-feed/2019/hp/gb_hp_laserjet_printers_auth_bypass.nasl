# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113368");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2019-04-08 10:45:55 +0000 (Mon, 08 Apr 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("HP LaserJet Printers Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hp/printer/http/detected");

  script_tag(name:"summary", value:"HP LaserJet Printers could allow a remote attacker to bypass
  security restrictions, caused by missing authentication for critical function. By sending a
  specially crafted request, an attacker could exploit this vulnerability to change configuration
  settings or gain administrative access.");

  script_tag(name:"vuldetect", value:"Tries to access administrative settings.");

  script_tag(name:"affected", value:"The following HP Printers are affected:

  - LaserJet P4014

  - LaserJet P4015

  - LaserJet 5200");

  script_tag(name:"solution", value:"Set an administrator password under the /password.html URL.");

  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/158953");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

#nb: CP4025 are sometimes detected as "CP4020", but they are still vulnerable
#nb: Same for P3015
#nb: CP Printers are sometimes detected as "laserjet" and sometimes as "color_laserjet"

cpe_list = make_list( "cpe:/h:hp:laserjet_p4014",
                      "cpe:/h:hp:laserjet_p4015",
                      "cpe:/h:hp:laserjet_5200",
                      "cpe:/h:hp:laserjet_cp4520",
                      "cpe:/h:hp:color_laserjet_cp4520",
                      "cpe:/h:hp:laserjet_cp4025",
                      "cpe:/h:hp:color_laserjet_cp4025",
                      "cpe:/h:hp:laserjet_cp4020",
                      "cpe:/h:hp:color_laserjet_cp4020",
                      "cpe:/h:hp:laserjet_p3015",
                      "cpe:/h:hp:laserjet_p3010" );

if( ! info = get_app_port_from_list( cpe_list: cpe_list, service: "www" ) )
  exit( 0 );

port = info["port"];
cpe = info["cpe"];

if( ! get_app_location( cpe: cpe, port: port, nofork: TRUE ) )
  exit( 0 );

url = "/password.html";

buf = http_get_cache( port: port, item: url );

if( buf =~ "Use the fields below to set or change the Administrator Password" ) {
  report = http_report_vuln_url( port: port, url: url );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
