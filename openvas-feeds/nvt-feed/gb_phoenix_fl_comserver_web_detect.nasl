# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140590");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-08 12:30:46 +0700 (Fri, 08 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("PHOENIX CONTACT FL COMSERVER Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of PHOENIX CONTACT FL COMSERVER devices.

The script sends a connection request to the server and attempts to detect PHOENIX CONTACT FL COMSERVER devices
and to extract its firmware version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.phoenixcontact.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/deviceinfo.htm";
res = http_get_cache(port: port, item: url);

if ('class="devicetyp">FL COMSERVER' >< res && "Phoenix Contact GmbH" >< res) {
  version = "unknown";

  mod = eregmatch(pattern: 'class="devicetyp">FL COMSERVER ([^<]+)', string: res);
  if (isnull(mod[1]))
    exit(0);

  model = mod[1];
  set_kb_item(name: "phoenix_comserver/model", value: model);

  vers = eregmatch(pattern: 'Firmware Version.*<p>.*E([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "phoenix_comserver/fw_version", value: version);
    concUrl = url;
  }

  mac = eregmatch(pattern: 'MAC Address.*([a-fA-F0-9:]{17})', string: res);
  if (!isnull(mac[1])) {
    extra = "Mac Address:   " + mac[1] + '\n';
    register_host_detail(name: "MAC", value: mac[1], desc: "gb_phoenix_fl_comserver_web_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: mac[1]);
  }

  set_kb_item(name: "phoenix_comserver/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:phoenixcontact:comserver_firmware:");
  if (!cpe)
    cpe = 'cpe:/o:phoenix_contact:comserver_firmware';

  register_product(cpe: cpe, install: "/", port: port, service: "www");
  os_register_and_report(os: "PHOENIX CONTACT FL COMSERVER Firmware", cpe: cpe,
                         desc: "PHOENIX CONTACT FL COMSERVER Detection (HTTP)", runs_key: "unixoide");

  log_message(data: build_detection_report(app: "PHOENIX CONTACT FL COMSERVER " + model, version: version,
                                           install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl,
                                           extra: extra),
              port: port);
  exit(0);
}

exit(0);
