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

CPE_PREFIX = "cpe:/h:qnap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813164");
  script_version("2022-05-30T10:35:56+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-30 10:35:56 +0000 (Mon, 30 May 2022)");
  script_tag(name:"creation_date", value:"2018-05-03 19:51:43 +0530 (Thu, 03 May 2018)");

  script_name("QNAP Photo Station Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of QNAP Photo Station.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("qnap/nas/http/detected");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

# nb: Photo Station is part of QNAP QTS but we're checking all NAS OS variants just to be sure...
if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

foreach dir (make_list("/photo", "/photo/gallery", "/gallery")) {
  req = http_get_req(url: dir + "/", port: port, add_headers: make_array("Accept-Encoding", "gzip, deflate"));
  res = http_keepalive_send_recv(port: port, data: req);

  if (res =~ "^HTTP/1\.[01] 30.") {
    url = eregmatch(pattern: 'Location: ([^\r\n]+)', string: res);
    if (url[1]) {
      new_url = url[1];
      req = http_get_req(url: new_url, port: port);
      res = http_keepalive_send_recv(port: port, data: req);
      if (res !~ "^HTTP/1\.[01] 200")
        continue;
    }
  }

  if (res =~ "^HTTP/1\.[01] 200" && "title>Photo Station</title" >< res) {
    url = eregmatch(pattern: "'\.js\?([0-9.]+)", string: res);
    new_url = dir + "/lang/ENG.js?" + url[1] ;

    req = http_get_req(url: new_url, port: port);
    res = http_keepalive_send_recv(port: port, data: req);

    if (res =~ "^HTTP/1\.[01] 200" && "QTS Login" >< res &&
        res =~ "COPYRIGHT=.*QNAP Systems" && "LANG_QTS" >< res) {
      version = "unknown";

      set_kb_item(name:"qnap/nas/photostation/detected", value:TRUE);
      set_kb_item(name:"qnap/nas/photostation/http/detected", value:TRUE);
      # nb: This one should be eventually dropped in the future:
      set_kb_item(name:"qnap/nas/PhotoStation/detected", value:TRUE);

      url = dir + "/api/user.php" ;
      req = http_get_req(url: url, port: port);
      res = http_keepalive_send_recv(port: port, data: req);

      if (res =~ "^HTTP/1\.[01] 200" && "status" >< res && "timestamp" >< res) {
        vers = eregmatch(pattern: '<appVersion>([0-9.]+)</appVersion><appBuildNum>([0-9]+)<', string: res);
        baseQTSVersion = eregmatch(pattern: '<builtinFirmwareVersion>([0-9.]+)</builtinFirmwareVersion>',
                                   string: res);
        if (!isnull(vers[1])) {
          version = vers[1];
          concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
          set_kb_item(name: "qnap/nas/PhotoStation/version", value: version);

          if (!isnull(vers[2])) {
            build = vers[2];
            set_kb_item(name: "qnap/nas/PhotoStation/build", value: build);
          }

          if (baseQTSVersion[1]) {
            baseQTSVer = baseQTSVersion[1];
            set_kb_item(name: "qnap/nas/PS/baseQTSVer", value: baseQTSVer);
          }
        }

        cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:qnap:photo_station:");
        if (!cpe)
          cpe = "cpe:/a:qnap:photo_station";

        register_product(cpe: cpe, location: dir, port: port, service: "www");

        log_message(data: build_detection_report(app: "QNAP Photo Station", version: version, install: dir,
                                                 cpe: cpe, concludedUrl: concUrl, concluded: vers[0]),
                    port:port);
        exit(0);
      }
    }
  }
}

exit(0);
