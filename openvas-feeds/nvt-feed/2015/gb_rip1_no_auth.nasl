# Copyright (C) 2015 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105236");
  script_version("2022-07-08T10:11:49+0000");
  script_tag(name:"last_modification", value:"2022-07-08 10:11:49 +0000 (Fri, 08 Jul 2022)");
  script_tag(name:"creation_date", value:"2015-03-13 09:16:37 +0100 (Fri, 13 Mar 2015)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("RIP-1 Poisoning Routing Table");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("rip_detect.nasl");
  script_require_udp_ports("Services/udp/rip", 520);
  script_mandatory_keys("rip-1/detected");

  script_tag(name:"summary", value:"This host is running a RIP-1 agent.");

  script_tag(name:"vuldetect", value:"Sends a RIP request and checks the response.");

  script_tag(name:"insight", value:"RIP-1 does not implement authentication. An attacker may feed
  the remote host with bogus routes and hijack network connections.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information
  that may lead to further attacks.");

  script_tag(name:"solution", value:"Disable the RIP agent if you don't use it, or use RIP-2 and
  implement authentication.");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port( default:520, ipproto:"udp", proto:"rip" );

if( get_kb_item( "rip-1/" + port + "/detected" ) ) {
  security_message( port:port, proto:"udp" );
  exit( 0 );
}

exit( 99 );
