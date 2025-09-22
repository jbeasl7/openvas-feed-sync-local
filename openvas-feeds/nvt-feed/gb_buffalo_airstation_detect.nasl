# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140995");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-04-18 13:00:04 +0700 (Wed, 18 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Buffalo AirStation Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Buffalo AirStation.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.buffalo-technology.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default: 8080);

res = http_get_cache(port: port, item: "/cgi-bin/cgi?req=twz");

if ('name="airstation_uname"' >< res && 'alt="BUFFALO"' >< res) {
  detected = TRUE;
  version = "unknown";

  url = "/cgi-bin/cgi?req=fnc&fnc=%24{get_json_param(DEVICE,1524028324602)}";
  header = make_array("X-Requested-With", "XMLHttpRequest",
                      "Content-type", "application/x-www-form-urlencoded");
  req = http_post_put_req(port: port, url: url, add_headers: header);
  res = http_keepalive_send_recv(port: port, data: req);

  vers = eregmatch(pattern: '"VERSION":"([0-9.]+)",', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  mod = eregmatch(pattern: '"MODEL":"([^"]+)', string: res);
  if (!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name: "buffalo_airstation/model", value: model);
  }

  buf = eregmatch(pattern: '"SUB_VERSION":"([0-9.]+)', string: res);
  if (!isnull(buf[1]))
    extra += 'Sub Version:   ' + buf[1] + '\n';
  buf = eregmatch(pattern: '"BOOT_VERSION":"([0-9.-]+)', string: res);
  if (!isnull(buf[1]))
    extra += 'Boot Version:  ' + buf[1] + '\n';

  set_kb_item(name: "buffalo/airstation/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:buffalo:" + tolower(model) + "_firmware:");
  if (!cpe)
    cpe = "cpe:/o:buffalo:" + tolower(model) + "_firmware";

  os_register_and_report(os: "Buffalo Airstation Firmware", cpe: cpe, desc: "Buffalo AirStation Detection (HTTP)", runs_key: "unixoide");

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Buffalo Airstation " + model, version: version, install: "/",
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra),
              port: port);
}

exit(0);
