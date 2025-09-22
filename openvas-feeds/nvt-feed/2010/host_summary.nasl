# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.810003");
  script_version("2022-07-27T10:11:28+0000");
  script_tag(name:"last_modification", value:"2022-07-27 10:11:28 +0000 (Wed, 27 Jul 2022)");
  script_tag(name:"creation_date", value:"2010-08-10 14:49:09 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Host Summary");
  # nb: Needs to run at the end of the scan because of the required info only available in this phase...
  script_category(ACT_END);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secspace_traceroute.nasl", "secpod_open_tcp_ports.nasl");

  script_tag(name:"summary", value:"This VT summarizes technical information about the scanned host
  collected during the scan.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

report = "traceroute:";
route = get_kb_item("traceroute/route");
if(route) {
  report += route;
}
report += '\n';

report += "TCP ports:";
ports = get_kb_item("Ports/open/tcp");
if(ports) {
  report += ports;
}
report += '\n';

report += "UDP ports:";
ports = get_kb_item("Ports/open/udp");
if(ports) {
  report += ports;
}
report += '\n';

log_message(proto:"HOST-T", data:report);
