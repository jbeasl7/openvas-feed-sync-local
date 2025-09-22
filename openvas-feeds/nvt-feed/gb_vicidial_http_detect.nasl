# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106837");
  script_version("2025-07-16T05:43:53+0000");
  script_tag(name:"last_modification", value:"2025-07-16 05:43:53 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-05-30 09:34:27 +0700 (Tue, 30 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("VICIdial Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of VICIdial.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.vicidial.com/");
  script_xref(name:"URL", value:"http://www.vicidial.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);
if (!http_can_host_php(port: port))
  exit(0);

url = "/vicidial/welcome.php";
res = http_get_cache(port: port, item: url);

if ("Agent Login" >< res && "vicidial/admin.php" >< res && "Timeclock" >< res) {
  version = "unknown";
  build = "unknown";
  install = "/";
  concUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  url = "/agc/vicidial.php";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # VERSION: 2.14-712c &nbsp; &nbsp; &nbsp; BUILD: 250326-2032
  # VERSION: 2.14-648c &nbsp; &nbsp; &nbsp; BUILD: 210720-0850
  # VERSION: 2.14-680c &nbsp; &nbsp; &nbsp; BUILD: 230304-0806
  # VERSION: 2.12-492c &nbsp; &nbsp; &nbsp; BUILD: 160428-1826
  vers = eregmatch(pattern: "VERSION: ([0-9a-z.-]+) &nbsp; &nbsp; &nbsp; BUILD: ([0-9-]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concluded = "  " + vers[0];
    concUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  if (!isnull(vers[2])) {
    build = vers[2];
    set_kb_item(name: "vicidial/build", value: build);
    extra = "  Build: " + build;
  }

  set_kb_item(name: "vicidial/detected", value: TRUE);
  set_kb_item(name: "vicidial/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9a-z.-]+)", base: "cpe:/a:vicidial:vicidial:");
  if (!cpe)
    cpe = "cpe:/a:vicidial:vicidial";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "VICIdial", version: version,
                                           install: install, cpe: cpe, concluded: concluded, concludedUrl: concUrl,
                                           extra: extra),
              port: port);
  exit(0);
}

exit(0);
