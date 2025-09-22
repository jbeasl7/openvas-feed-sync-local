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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103598");
  script_version("2022-06-03T06:21:25+0000");
  script_tag(name:"last_modification", value:"2022-06-03 06:21:25 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2012-10-29 15:28:00 +0100 (Mon, 29 Oct 2012)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Lantronix Remote Configuration Protocol Password Disclosure");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_lantronix_mgm_udp_detect.nasl", "gb_lantronix_mgm_tcp_detect.nasl");
  script_mandatory_keys("lantronix_device/lantronix_remote_conf/password_gathered");

  script_tag(name:"summary", value:"Lantronix Devices are prone to a Password Disclosure via the
  remote configuration protocol.

  It was possible to retrieve the setup record from Lantronix devices via the
  config port (30718/udp or 30718/tcp, enabled by default) and to extract the
  Telnet/HTTP password.");

  script_tag(name:"solution", value:"Disable access to UDP port 30718 and/or TCP port 30718.");

  exit(0);
}

include("port_service_func.inc");

default_ports = make_list( 30718 );

report = 'The device is disclosing the following password(s) (password:port/protocol):\n';

udp_ports = service_get_ports( default_port_list:default_ports, proto:"lantronix_remote_conf", ipproto:"udp" );

foreach port( udp_ports ) {
  if( ! pass = get_kb_item( "lantronix_device/lantronix_remote_conf_udp/" + port + "/password" ) ) continue;
  report += '\n' + pass + ':' + port + '/udp';
  found = TRUE;
}

tcp_ports = service_get_ports( default_port_list:default_ports, proto:"lantronix_remote_conf" );

foreach port( tcp_ports ) {
  if( ! pass = get_kb_item( "lantronix_device/lantronix_remote_conf_tcp/" + port + "/password" ) ) continue;
  report += '\n' + pass + ':' + port + '/tcp';
  found = TRUE;
}

if( found ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
