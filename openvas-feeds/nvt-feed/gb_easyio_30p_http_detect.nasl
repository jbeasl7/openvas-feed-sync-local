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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142369");
  script_version("2021-06-18T10:02:21+0000");
  script_tag(name:"last_modification", value:"2021-06-18 10:02:21 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2019-05-06 08:18:30 +0000 (Mon, 06 May 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("EasyIO 30P Controller Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of EasyIO 30P controllers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.easyio.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/main.js";
res = http_get_cache(port: port, item: url);

if ("EasyIO-30P Sedona" >< res && 'GDM name' >< res) {
  version = "unknown";

  # [1,"Model"],[2,"<span id=GDM name=GDM>IO-30S-BM</span>"]
  mod = eregmatch(pattern: 'Model"[^"]+"<span id=GDM name=GDM>([^<]+)', string: res);
  if (!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name: "easyio_30p/model", value: model);
    extra = "Model: " + model;
  }

  # [1,"Application Software Version"],[2,"<span id=GDV name=GDV>2.0.5.25</span>"]
  vers = eregmatch(pattern: 'Application Software Version"[^"]+"<span id=GDV name=GDV>([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  set_kb_item(name: "easyio_30p/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:easyio:easyio_30p_firmware:");
  if (!cpe)
    cpe = "cpe:/o:easyio:easyio_30p_firmware";

  os_register_and_report(os: "EasyIO 30P Controller Firmware", cpe: cpe, runs_key: "unixoide",
                         desc: "EasyIO 30P Controller Detection (HTTP)");

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "EasyIO 30P Controller", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
