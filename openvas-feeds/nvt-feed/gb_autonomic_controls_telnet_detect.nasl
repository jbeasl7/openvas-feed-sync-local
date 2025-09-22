# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113243");
  script_version("2022-01-18T10:52:27+0000");
  script_tag(name:"last_modification", value:"2022-01-18 10:52:27 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2018-08-07 10:33:33 +0200 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Autonomic Controls Detection (Telnet)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/autonomic_controls/device/detected");

  script_tag(name:"summary", value:"Telnet based detection of Autonomic Controls devices.");

  script_xref(name:"URL", value:"http://www.autonomic-controls.com/products/");

  exit(0);
}

include("host_details.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port( default: 23 );

if( ! banner = telnet_get_banner( port: port ) )
  exit( 0 );

if( banner =~ "Autonomic Controls" ) {

  set_kb_item( name: "autonomic_controls/detected", value: TRUE );
  set_kb_item( name: "autonomic_controls/telnet/port", value: port );

  ver = eregmatch( string: banner, pattern: "Autonomic Controls Remote Configuration version ([0-9.]+)", icase: TRUE );
  if( ! isnull( ver[1] ) ) {
    set_kb_item( name: "autonomic_controls/telnet/version", value: ver[1] );
    set_kb_item( name: "autonomic_controls/telnet/concluded", value: ver[0] );
  }
}

exit( 0 );
