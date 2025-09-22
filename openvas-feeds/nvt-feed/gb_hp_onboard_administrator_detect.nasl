# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103794");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2013-10-01 10:46:38 +0200 (Tue, 01 Oct 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HP/HPE Onboard Administrator Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of HP/HPE Onboard Administrator.

  The script sends a connection request to the server and attempts to detect HP/HPE Onboard Administrator and to extract
  its version.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:443);

url = "/xmldata?item=All";
buf = http_get_cache(port:port, item:url);

if(buf !~ "<PN>.*Onboard Administrator.*</PN>" || "<FWRI>" >!< buf)
  exit(0);

version = "unknown";

vers = eregmatch(pattern:"<FWRI>([^<]+)</FWRI>", string:buf);
if(!isnull(vers[1]))
  version = vers[1];

set_kb_item(name:"hp/onboard_administrator/detected", value:TRUE);

app_cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:hp:onboard_administrator:");
if(!app_cpe)
  app_cpe = "cpe:/a:hp:onboard_administrator";

os_cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/o:hpe:onboard_administrator_firmware:");
if(!os_cpe)
  os_cpe = "cpe:/o:hpe:onboard_administrator_firmware";

register_product(cpe:app_cpe, location:"/", port:port, service:"www");
register_product(cpe:os_cpe, location:"/", port:port, service:"www");
os_register_and_report(os:"HP/HPE Onboard Administrator Firmware", cpe:os_cpe, desc:"HP/HPE Onboard Administrator Detection (HTTP)", runs_key:"unixoide");

report = build_detection_report(app:"HP/HPE Onboard Administrator", version:version, install:"/", cpe:app_cpe,
                                concluded:vers[0], concludedUrl:http_report_vuln_url(port:port, url:url, url_only:TRUE));
report += '\n\n';
report += build_detection_report(app:"HP/HPE BladeSystem c-Class", skip_version:TRUE, install:"/", cpe:"cpe:/h:hpe:bladesystem_c-class");

log_message(data:report, port:port);
exit(0);
