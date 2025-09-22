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
  script_oid("1.3.6.1.4.1.25623.1.0.143177");
  script_version("2022-06-03T10:04:55+0000");
  script_tag(name:"last_modification", value:"2022-06-03 10:04:55 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2019-11-26 04:42:17 +0000 (Tue, 26 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache ZooKeeper Detection (TCP)");

  script_tag(name:"summary", value:"TCP based detection of Apache ZooKeeper.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 2181);

  script_xref(name:"URL", value:"https://zookeeper.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("port_service_func.inc");

port = unknownservice_get_port(default: 2181);

extra = "Full server response(s)";
version = "unknown";

# https://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_zkCommands
# nb:
# - The "srvr" command seems to be only available since version 3.3.0
# - Since version 3.5.3 there is a whitelist of commands (zookeeper.4lw.commands.whitelist). By
#   default this whitelist only contains the "srvr" command.
# Because of these points we need to check both commands.
cmds = make_list("stat", "srvr");
foreach cmd(cmds) {

  # nb: Apache ZooKeeper seems to require sending each command separately...
  if (!soc = open_sock_tcp(port))
    continue;

  send(socket: soc, data: cmd);
  res = recv(socket: soc, length: 2048);
  close(soc);
  if (!res)
    continue;

  if ("Zookeeper version: " >< res) {
    found = TRUE;
    extra += '\n\n- for command "' + cmd + '":\n' + chomp(res);
    if (version == "unknown") {
      vers = eregmatch(pattern: "Zookeeper version: ([0-9.]+)", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concluded = vers[0];
      }
    }
  }

  if (res == cmd + ' is not executed because it is not in the whitelist.\n' ) {
    found = TRUE;
    extra += '\n\n- for command "' + cmd + '":\n' + chomp(res);
  }
}

# Zookeeper version: 3.4.14-4c25d480e66aadd371de8bd2fd8da255ac140bcf, built on 03/06/2019 16:18 GMT
# Clients:
#  /127.0.0.1:56814[1](queued=0,recved=1119291,sent=1119295)
#
# Latency min/avg/max: 0/0/23
# Received: 1119410
# Sent: 1119413
# Connections: 2
# Outstanding: 0
# Zxid: 0xca
# Mode: standalone
# Node count: 156
#
# or:
#
# Zookeeper version: 3.6.2--803c7f1a12f85978cb049af5e4ef23bd8b688715, built on 09/04/2020 12:44 GMT
# *snip* (remaining info is the same as above)
#
# Note that the difference between the response on the "stat" command vs. "srvr" is that the first
# includes "Clients:" part while the latter doesn't include that one.
#
# Or if command is disabled:
#
# stat is not executed because it is not in the whitelist.
# srvr is not executed because it is not in the whitelist.
#
if (found) {

  install = port + "/tcp";

  set_kb_item(name: "apache/zookeeper/detected", value: TRUE);
  set_kb_item(name: "apache/zookeeper/tcp/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:zookeeper:");
  if (!cpe)
    cpe = "cpe:/a:apache:zookeeper";

  service_register(port: port, ipproto: "tcp", proto: "zookeeper");
  register_product(cpe: cpe, location: install, port: port, service: "zookeeper");

  report = build_detection_report(app: "Apache ZooKeeper", version: version, install: install, cpe: cpe,
                                  concluded: concluded);
  report += '\n\n' + extra;

  log_message(port: port, data: report);
}

exit(0);
