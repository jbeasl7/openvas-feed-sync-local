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
  script_oid("1.3.6.1.4.1.25623.1.0.141141");
  script_version("2022-11-08T10:12:11+0000");
  script_tag(name:"last_modification", value:"2022-11-08 10:12:11 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"creation_date", value:"2018-06-06 08:31:40 +0700 (Wed, 06 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei iBMC Detection (UPnP)");

  script_tag(name:"summary", value:"UPnP based detection of Huawei iBMC over UPnP.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_upnp_udp_detect.nasl");
  script_require_udp_ports("Services/udp/upnp", 1900);
  script_mandatory_keys("upnp/identified");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port(default: 1900, ipproto: "udp", proto: "upnp");

if (!banner = get_kb_item("upnp/" + port + "/banner"))
  exit(0);

if (" iBMC/" >!< banner)
  exit(0);

version = "unknown";
model = "unknown";

set_kb_item(name: "huawei/ibmc/detected", value: TRUE);
set_kb_item(name: "huawei/data_communication_product/detected", value: TRUE);
set_kb_item(name: "huawei/ibmc/upnp/port", value: port);
set_kb_item(name: "huawei/ibmc/upnp/" + port + "/concluded", value: egrep(pattern: " iBMC", string: banner));

# SERVER: UPnP/2.0 iBMC/2.96 ProductName/2288H SN/
# SERVER: UPnP/2.0 iBMC/3.00 ProductName/2288H V5 SN/2102312BTHN0JA000008
vers = eregmatch(pattern: "iBMC/([0-9.]+)", string: banner);
if (!isnull(vers[1]))
  version = vers[1];

mod = eregmatch(pattern: "ProductName/([^SN/]+)", string: banner);
if (!isnull(mod[1]))
  model = chomp(mod[1]);

set_kb_item(name: "huawei/ibmc/upnp/" + port + "/version", value: version);
set_kb_item(name: "huawei/ibmc/upnp/" + port + "/model", value: model);

exit(0);
