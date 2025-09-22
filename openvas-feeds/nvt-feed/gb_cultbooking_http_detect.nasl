# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148173");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-05-24 09:16:07 +0000 (Tue, 24 May 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("CultBooking Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of CultBooking.");

  script_xref(name:"URL", value:"https://www.cultbooking.com/en/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/cb", "/cultbooking", "/CultBooking", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  url = dir + "/login";
  res = http_get_cache(port: port, item: url);

  if ("<title>CultBooking</title>" >< res || "We're sorry but cultbooking-frontend" >< res) {
    version = "unknown";

    set_kb_item(name: "cultbooking/detected", value: TRUE);
    set_kb_item(name: "cultbooking/http/detected", value: TRUE);

    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    cpe = "cpe:/a:cultuzz:cultbooking";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "CultBooking", version: version, install: install,
                                             cpe: cpe, concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);
