# Copyright (C) 2005 by Noam Rathaus, Beyond Security Ltd.
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
  script_oid("1.3.6.1.4.1.25623.1.0.10344");
  script_version("2021-04-15T08:31:15+0000");
  script_tag(name:"last_modification", value:"2021-04-15 08:31:15 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Napster Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Beyond Security");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(6699);

  script_tag(name:"summary", value:"Detection of Napster.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = 6699;
if(!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

res = recv(socket:soc, length:50);
if(res && "1" >< res) {

  data = string("GET\r\n");
  send(socket:soc, data:data);
  res = recv(socket:soc, length:50);
  if(!res) {

    data = string("GET /\r\n");
    send(socket:soc, data:data);
    res = recv(socket:soc, length:150);

    if("FILE NOT SHARED" >< res) {
      report = "Napster was detected on the target system.";
      log_message(data:report, port:port);
      service_register(proto:"napster", port:port);
    }
  }
}

close(soc);

exit(0);