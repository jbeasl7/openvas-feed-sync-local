# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106588");
  script_version("2022-09-05T10:11:01+0000");
  script_tag(name:"last_modification", value:"2022-09-05 10:11:01 +0000 (Mon, 05 Sep 2022)");
  script_tag(name:"creation_date", value:"2017-02-16 09:18:30 +0700 (Thu, 16 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa NPort Device Detection (Telnet)");

  script_tag(name:"summary", value:"Telnet based detection of Moxa NPort devices.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/moxa/nport/detected");

  exit(0);
}

#include("cpe.inc");
include("host_details.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port(default: 23);
banner = telnet_get_banner(port: port);

# Model name       : NPort 5150A
# MAC address      : 00:90:E7:20:1F:00
# Serial No.       : 6621
# Firmware version : 1.4 Build 17030709
# System uptime    : 78 days, 13h:59m:22s
#
# Please keyin your password:
if (!banner || banner =~ "MiiNePort" || banner =~ "MGate" ||
   ("Please keyin your password" >!< banner && "Please keyin your username" >!< banner))
  exit(0);

mod = eregmatch(pattern: 'Model name\\s*:\\s(NPort )?([^ \r\n]+)', string: banner);
if (isnull(mod[2]))
  exit(0);

version = "unknown";
build = "unknown";

set_kb_item(name: "moxa/nport/detected", value: TRUE);
set_kb_item(name: "moxa/nport/telnet/detected", value: TRUE);
set_kb_item(name: "moxa/nport/telnet/port", value: port);
set_kb_item(name: "moxa/nport/telnet/" + port + "/concluded", value: banner);

set_kb_item(name: "moxa/nport/telnet/" + port + "/model", value: mod[2]);

# nb: Strip away unprintable characters (e.g. \u000d. as seen on some responses) for version etc.
#     (but not for the model above)
banner = bin2string(ddata: banner, noprint_replacement: " ");

vers = eregmatch(pattern: 'Firmware version\\s*:\\s*([0-9.]+) Build ([0-9]+[^ \r\n])', string: banner);
if (!isnull(vers[1]))
  version  = vers[1];

if (!isnull(vers[2]))
  build = vers[2];

mac = eregmatch(pattern: 'MAC address\\s*:\\s*([^ \r\n]+)', string: banner);
if (!isnull(mac[1])) {
  register_host_detail(name: "MAC", value: mac[1], desc: "Moxa NPort Device Detection (Telnet)");
  replace_kb_item(name: "Host/mac_address", value: mac[1]);
}

set_kb_item(name: "moxa/nport/telnet/" + port + "/version", value: version);
set_kb_item(name: "moxa/nport/telnet/" + port + "/build", value: build);

exit(0);
