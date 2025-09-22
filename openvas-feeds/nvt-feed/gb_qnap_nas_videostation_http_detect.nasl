# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/h:qnap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146084");
  script_version("2022-05-30T10:35:56+0000");
  script_tag(name:"last_modification", value:"2022-05-30 10:35:56 +0000 (Mon, 30 May 2022)");
  script_tag(name:"creation_date", value:"2021-06-07 04:34:23 +0000 (Mon, 07 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("QNAP Video Station Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of QNAP Video Station.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("qnap/nas/http/detected");

  script_xref(name:"URL", value:"https://www.qnap.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

# nb: Video Station is part of QNAP QTS but we're checking all NAS OS variants just to be sure...
if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

res = http_get_cache(port: port, item: "/video/");

if ("<title>Video Station</title>" >< res && "__REACT_DEVTOOLS_GLOBAL_HOOK__" >< res) {
  version = "unknown";
  install = "/video";

  url = "/video/api/user.php";

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # <QDocRoot version="1.0"><status>0</status><msg>authentication failed.</msg><builtinFirmwareVersion>4.3.3</builtinFirmwareVersion><appVersion>5.1.6</appVersion><appBuildNum>20190325</appBuildNum><HLS_Enable>0</HLS_Enable><func_bits>0</func_bits><is_g>0</is_g><auth>1</auth></QDocRoot>
  vers = eregmatch(pattern: "<appVersion>([0-9.]+)<", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  set_kb_item(name: "qnap/videostation/detected", value: TRUE);
  set_kb_item(name: "qnap/videostation/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:qnap:video_station:");
  if (!cpe)
    cpe = "cpe:/a:qnap:video_station";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "QNAP Video Station", version: version, cpe: cpe,
                                           install: install, concluded: vers[0], concludedUrl: concUrl),
              port: port);
}

exit(0);
