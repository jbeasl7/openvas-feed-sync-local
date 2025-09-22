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
  script_oid("1.3.6.1.4.1.25623.1.0.108526");
  script_version("2022-06-03T06:21:25+0000");
  script_tag(name:"last_modification", value:"2022-06-03 06:21:25 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2019-01-08 09:37:20 +0100 (Tue, 08 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("AppleShare IP / Apple Filing Protocol (AFP) Unencrypted Cleartext Login");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("asip-status.nasl");
  script_mandatory_keys("asip_afp/iscleartext");

  script_tag(name:"summary", value:"The remote host is running a AppleShare IP / Apple Filing Protocol (AFP) service that
  allows cleartext logins over unencrypted connections.");

  script_tag(name:"impact", value:"An attacker can uncover login names and passwords by sniffing traffic to the
  AppleShare IP / Apple Filing Protocol (AFP) service.");

  script_tag(name:"solution", value:"Enable encryption within the service configuration. Please have a look at the
  manual of the software providing this service for more information on the configuration.");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port( default:548, proto:"appleshare" );


if( ! get_kb_item( "asip_afp/" + port + "/iscleartext" ) )
  exit( 99 );

uams = get_kb_item( "asip_afp/" + port + "/uams" );
if( uams )
  report = 'The following UAMs including the "Cleartxt Passwrd" are reported by the service:\n\n' + uams;

security_message( port:port, data:report );
exit( 0 );
