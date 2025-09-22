# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140400");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-09-26 16:12:38 +0700 (Tue, 26 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("FLIR Systems Camera Detection");

  script_tag(name:"summary", value:"Detection of FLIR Systems Cameras.

  The script sends a connection request to the server and attempts to detect FLIR Systems Cameras and to extract
  its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.flir.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8081);

res = http_get_cache(port: port, item: "/");

if ("<title>FLIR Systems, Inc. </title>" >< res && 'id="sensortype"' >< res && ("DIALOG_SEC_PASS_CUR" >< res || "securityPassCurrentLabel" >< res)) {
  version = "unknown";

  vers = eregmatch(pattern: "flir\.base\.js\?_v=([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "flir_camera/version", value: version);
  }

  model_match = eregmatch(pattern: '<input type="hidden" id="productName" value="([^\"\n]+)', string: res, icase: TRUE);
  if (!isnull(model_match[1])) {
    model = model_match[1];
    set_kb_item(name: "flir_camera/model", value: model);
  }

  set_kb_item(name: "flir_camera/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:flir_systems:camera:");
  if (!cpe)
    cpe = 'cpe:/a:flir_systems:camera';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "FLIR Systems Camera", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
