# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802236");
  script_version("2021-10-20T09:03:29+0000");
  script_tag(name:"last_modification", value:"2021-10-20 09:03:29 +0000 (Wed, 20 Oct 2021)");
  script_tag(name:"creation_date", value:"2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-1999-0612");
  script_name("Finger Service Remote Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl");
  script_require_ports("Services/finger", 79);

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/reference/vuln/finger-running.htm");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to obtain
  sensitive information that could aid in further attacks.");

  script_tag(name:"affected", value:"GNU finger is known to be affected. Other finger
  implementations might be affected as well.");

  script_tag(name:"insight", value:"The flaw exists because the finger service exposes valid user
  information to any entity on the network.

  Remark: NIST don't see 'configuration issues' as software flaws so the referenced CVE has a
  severity of 0.0. The severity of this VT has been raised by Greenbone to still report a
  configuration issue on the target.");

  script_tag(name:"summary", value:"The finger service on the remote host is prone to an information
  disclosure vulnerability.");

  script_tag(name:"solution", value:"Disable the finger service, or install a finger service or
  daemon that limits the type of information provided.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port( default:79, proto:"finger" );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

banner = recv( socket:soc, length:2048, timeout:5 );
if( banner ) {
  close( soc );
  exit( 0 );
}

send( socket:soc, data:string( "root\r\n" ) );
res = recv( socket:soc, length:2048 );
close( soc );
if( ! res )
  exit( 0 );

if( "Login" >< res || "User" >< res || "logged" >< res ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );