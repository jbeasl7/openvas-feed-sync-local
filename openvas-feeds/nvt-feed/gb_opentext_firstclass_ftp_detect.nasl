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
  script_oid("1.3.6.1.4.1.25623.1.0.113609");
  script_version("2022-01-18T10:52:27+0000");
  script_tag(name:"last_modification", value:"2022-01-18 10:52:27 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2019-12-02 13:47:37 +0200 (Mon, 02 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenText FirstClass Detection (FTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/opentext/firstclass/detected");

  script_tag(name:"summary", value:"FTP based detection of OpenText FirstClass.");

  script_xref(name:"URL", value:"https://www.opentext.com/products-and-solutions/products/specialty-technologies/firstclass");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default: 80 );

if( ! banner = ftp_get_banner( port: port ) )
  exit( 0 );

if( banner =~ "FTP server \(FirstClass" ) {

  set_kb_item( name: "opentext/firstclass/detected", value: TRUE );
  set_kb_item( name: "opentext/firstclass/ftp/detected", value: TRUE );
  set_kb_item( name: "opentext/firstclass/ftp/port", value: port );

  ver = eregmatch( string: banner, pattern: "FirstClass v([0-9.]+)", icase: TRUE );
  if( ! isnull ( ver[1] ) ) {
    set_kb_item( name: "opentext/firstclass/ftp/concluded", value: ver[0] );
    set_kb_item( name: "opentext/firstclass/ftp/version", value: ver[1] );
  }
}

exit( 0 );
