# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106667");
  script_version("2026-02-24T05:57:09+0000");
  script_tag(name:"last_modification", value:"2026-02-24 05:57:09 +0000 (Tue, 24 Feb 2026)");
  script_tag(name:"creation_date", value:"2017-03-17 14:27:26 +0700 (Fri, 17 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Weblate Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Weblate.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl",  "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://weblate.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 80);

sub_urls = make_list("/", "/about");

foreach dir (make_list_unique("/weblate", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  foreach suburl (sub_urls) {
    url = dir + suburl;
    location = url;

    res = http_get_cache(port: port, item: url);

    if ((res =~ "<title>.*About Weblate.*</title>" && ('"panel-title">Versions' >< res || 'panel-title">Weblate is built' >< res)) || res =~ "Powered by <[^>]+>Weblate ") {
      version = "unknown";
      conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

      set_kb_item(name: "weblate/detected", value: TRUE);
      set_kb_item(name: "weblate/http/detected", value: TRUE);

      if (vers = eregmatch(pattern: "Weblate</a></th>.<td>([0-9.]+)</td>", string: res) ) {
        version = vers[1];
      }

      # Powered by <a href="https://weblate.org/?utm_source=weblate&amp;utm_term=3.8">Weblate 3.8
      # Powered by <a href="https://weblate.org/">Weblate 5.13</a>
      # Powered by <a href="https://weblate.org/">Weblate 5.16</a>
      else if (vers = eregmatch(pattern: "Powered by <[^>]+>Weblate ([0-9.]+)", string: res)) {
        version = vers[1];
      }

      cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:weblate:weblate:");
      if (!cpe)
        cpe = "cpe:/a:weblate:weblate";

      register_product(cpe: cpe, location: location, port: port, service: "www");

      log_message(data: build_detection_report(app: "Weblate", version: version, install: location,
                                               cpe: cpe, concluded: vers[0],
                                               concludedUrl: conclUrl),
                  port: port);
      exit(0);
    }
  }
}

exit(0);
