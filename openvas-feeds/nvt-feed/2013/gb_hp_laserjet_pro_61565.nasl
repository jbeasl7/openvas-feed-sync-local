# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/h:hp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103757");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2013-08-12 16:59:44 +0200 (Mon, 12 Aug 2013)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");

  script_cve_id("CVE-2013-4807");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Multiple HP LaserJet Pro Printers Information Disclosure Vulnerability (Aug 2013)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Multiple HP LaserJet Pro Printers are prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Request /dev/save_restore.xml and read the response.");

  script_tag(name:"insight", value:"The hidden URL '/dev/save_restore.xml' contains a hex
  representation of the admin password in plaintext and no authentication is needed to access this
  site.");

  script_tag(name:"impact", value:"The vulnerability could be exploited remotely to gain
  unauthorized access to data.");

  script_tag(name:"affected", value:"HP LaserJet Pro P1102w

  HP LaserJet Pro P1606dn

  HP LaserJet Pro M1212nf MFP

  HP LaserJet Pro M1213nf MFP

  HP LaserJet Pro M1214nfh MFP

  HP LaserJet Pro M1216nfh MFP

  HP LaserJet Pro M1217nfw MFP

  HP LaserJet Pro M1218nfs MFP

  HP LaserJet Pro CP1025nw");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c03825817");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

cpe = infos["cpe"];

if( "laserjet" >!< cpe )
  exit( 99 );

port = infos["port"];

if( ! get_app_location( cpe:cpe, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/dev/save_restore.xml";
req = http_get( item:url, port:port );
buf = http_send_recv( port:port, data:req );

if( "<name>e_HttpPassword</name>" >< buf ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
