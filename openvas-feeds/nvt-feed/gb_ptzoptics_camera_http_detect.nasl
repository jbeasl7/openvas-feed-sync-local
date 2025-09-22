# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155078");
  script_version("2025-08-01T15:45:48+0000");
  script_tag(name:"last_modification", value:"2025-08-01 15:45:48 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-01 04:48:52 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("PTZOptics Camera Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of PTZOptics Camera devices.");

  script_xref(name:"URL", value:"https://ptzoptics.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/js/hisApplicationContext.js";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res !~ "^HTTP/1\.[01] 200" || "ptztypedef" >!< res || "ptzport" >!< res)
  exit(0);

model = "unknown";
version = "unknown";
location = "/";
conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "ptzoptics/camera/detected", value: TRUE);
set_kb_item(name: "ptzoptics/camera/http/detected", value: TRUE);

url = "/cgi-bin/param.cgi?get_device_conf";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

# devname="ptzoptics" mirrors="https://firmware.ptzoptics.com/" versioninfo="SOC v9.1.34" serial_num="<redacted>" device_model=" F64.HI "
mod = eregmatch(pattern: 'device_model\\s*=\\s*"\\s*([^"]+)"', string: res);
if (!isnull(mod[1])) {
  model = chomp(mod[1]);
  set_kb_item(name: "ptzoptics/camera/model", value: model);
  conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

vers = eregmatch(pattern: 'versioninfo\\s*=\\s*"SOC v([0-9.]+)"', string: res);
if (!isnull(vers[1])) {
  version = vers[1];
  if (url >!< conclUrl)
    conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

if (model != "unknown") {
  os_name = "PTZOptics " + model + " Firmware";
  hw_name = "PTZOptics " + model;

  os_cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                     base: "cpe:/o:ptzoptics:" + tolower(model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:ptzoptics:" + tolower(model) + "_firmware";

  hw_cpe = "cpe:/h:ptzoptics:" + tolower(model);
} else {
  os_name = "PTZOptics Camera Firmware";
  hw_name = "PTZOptics Camera Unknown Model";

  os_cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:ptzoptics:camera_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:ptzoptics:camera_firmware";

  hw_cpe = "cpe:/h:ptzoptics:camera";
}

os_register_and_report(os: os_name, cpe: os_cpe, port: port, runs_key: "unixoide",
                       desc: "PTZOptics Camera Detection (HTTP)");

register_product(cpe: os_cpe, location: location, port: port, service: "www");
register_product(cpe: hw_cpe, location: location, port: port, service: "www");

report = build_detection_report(app: os_name, version: version, install: location, cpe: os_cpe,
                                concluded: vers[0], concludedUrl: conclUrl);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe,
                                 concluded: mod[0]);

log_message(port: port, data: report);

exit(0);
