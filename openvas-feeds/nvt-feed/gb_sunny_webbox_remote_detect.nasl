# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.808203");
  script_version("2021-06-24T08:55:37+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-06-24 08:55:37 +0000 (Thu, 24 Jun 2021)");
  script_tag(name:"creation_date", value:"2016-05-24 10:37:42 +0530 (Tue, 24 May 2016)");
  script_name("Sunny WebBox Detection (HTTP)");

  script_tag(name:"summary", value:"Detects the installed version of
  SMA Solar Technology AG Sunny WebBox.

  This script check the presence of SMA Solar Technology AG Sunny WebBox from the
  banner.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("WebBox/banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port:port);
if(!banner)
  exit(0);

if(concl = egrep(string:banner, pattern:"Server: WebBox", icase:TRUE)) {

  concl = chomp(concl);
  version = "unknown";

  set_kb_item(name:"Sunny/WebBox/Installed", value:TRUE);

  cpe = "cpe:/o:sma_solar_technology_ag:webbox_firmware";

  os_register_and_report(os:"SMA Solar Sunny WebBox Firmware", cpe:cpe, runs_key:"unixoide",
                         desc:"Sunny WebBox Detection (HTTP)");

  register_product(cpe:cpe, location:"/", port:port, service:"www");

  log_message(data:build_detection_report(app:"SMA Solar Sunny WebBox",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:concl),
              port:port);
}

exit(0);
