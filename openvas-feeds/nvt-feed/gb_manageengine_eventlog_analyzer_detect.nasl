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
  script_oid("1.3.6.1.4.1.25623.1.0.140952");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"creation_date", value:"2018-04-06 11:12:19 +0700 (Fri, 06 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine EventLog Analyzer Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of ManageEngine EventLog Analyzer.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8400);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.manageengine.com/products/eventlog/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8400);

url = "/event/index3.do";

res = http_get_cache(port: port, item: url);

if ("<title>ManageEngine EventLog Analyzer" >< res &&
    ("Unlock the Real Value" >< res || "EventLog Authentication" >< res)) {
  version = "unknown";

  # var currentbuildNumber = '12141';
  vers = eregmatch(pattern: "currentbuildNumber = '([0-9]+)'", string: res);
  if (!isnull(vers[1]))
    version = vers[1];
  else {
    # <title>ManageEngine EventLog Analyzer 11</title>
    # This is not that reliable since no build information available
    vers = eregmatch(pattern: "<title>ManageEngine EventLog Analyzer ([0-9.]+)<", string: res);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  set_kb_item(name: "manageengine/products/detected", value: TRUE);
  set_kb_item(name: "manageengine/products/http/detected", value: TRUE);
  set_kb_item(name: "manageengine/eventlog_analyzer/detected", value: TRUE);
  set_kb_item(name: "manageengine/eventlog_analyzer/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:zohocorp:manageengine_eventlog_analyzer:");
  if (!cpe)
    cpe = "cpe:/a:zohocorp:manageengine_eventlog_analyzer";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "ManageEngine EventLog Analyzer", version: version,
                                           install: "/", cpe: cpe, concluded: vers[0],
                                           concludedUrl: http_report_vuln_url(port: port, url: url, url_only: TRUE)),
              port: port);
  exit(0);
}

exit(0);
