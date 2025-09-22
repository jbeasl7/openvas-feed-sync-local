# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114099");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-05-14 14:09:25 +0200 (Tue, 14 May 2019)");
  script_name("Pearl IP Cameras Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Pearl IP Cameras.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

#Note: This software is nearly identical to the one used by Beward -> gb_beward_ip_camera_http_detect.nasl
#and nearly identical to the one used by Zavio -> gb_zavio_ip_cameras_detect.nasl
#as well as TP-Link -> gb_tp_link_ip_cameras_detect.nasl

port = http_get_port(default: 80);

url = "/profile";
res = http_get_cache(port: port, item: url);

#initProdNbr="PX-3690"; initBrand="Pearl";
if(res =~ 'initProdNbr="([^"]+)";' && (res =~ 'BrandCopyright="Pearl\\s*";' || res =~ 'initBrand="Pearl\\s*";')) {
  version = "unknown";
  model = "unknown";

  mod = eregmatch(pattern: 'initProdNbr="([^"]+)";', string: res);
  if(!isnull(mod[1])) {
    model = string(mod[1]);
  }

  set_kb_item(name: "pearl/ip_camera/detected", value: TRUE);
  if(model != "unknown") {
    cpe_model = str_replace(string: tolower(model), find: " ", replace: "_");
    hw_cpe = "cpe:/h:pearl:ip_camera_" + cpe_model + ":";
    os_cpe = "cpe:/o:pearl:ip_camera_" + cpe_model + "_firmware";
    os_name = "Pearl IP Camera " + model + " Firmware";
    extra_info = "Detected model: " + model;
  } else {
    hw_cpe = "cpe:/h:pearl:ip_camera_unknown_model:";
    os_cpe = "cpe:/o:pearl:ip_camera_unknown_model_firmware";
  }

  os_register_and_report(os: os_name, cpe: os_cpe, desc: "Pearl IP Cameras Detection (HTTP)", runs_key: "unixoide");

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Pearl IP Camera",
                          ver: version,
                          base: hw_cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl,
                          extra: extra_info);
}

exit(0);
