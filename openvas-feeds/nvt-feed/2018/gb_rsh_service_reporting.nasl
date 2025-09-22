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
  script_oid("1.3.6.1.4.1.25623.1.0.100080");
  script_version("2021-10-20T09:03:29+0000");
  script_tag(name:"last_modification", value:"2021-10-20 09:03:29 +0000 (Wed, 20 Oct 2021)");
  script_tag(name:"creation_date", value:"2018-10-23 12:59:40 +0200 (Tue, 23 Oct 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0651");
  script_name("rsh Unencrypted Cleartext Login");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Useless services");
  script_dependencies("rsh.nasl");
  script_mandatory_keys("rsh/detected");

  script_tag(name:"summary", value:"This remote host is running a rsh service.");

  script_tag(name:"insight", value:"rsh (remote shell) is a command line computer program which can
  execute shell commands as another user, and on another computer across a computer network.

  Remark: NIST don't see 'configuration issues' as software flaws so the referenced CVE has a
  severity of 0.0. The severity of this VT has been raised by Greenbone to still report a
  configuration issue on the target.");

  script_tag(name:"solution", value:"Disable the rsh service and use alternatives like SSH
  instead.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port( default:514, proto:"rsh" );

if( ! get_kb_item( "rsh/" + port + "/detected" ) )
  exit( 99 );

if( ! report = get_kb_item( "rsh/" + port + "/service_report" ) )
  exit( 99 );

security_message( port:port, data:report );
exit( 0 );