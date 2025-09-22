# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{

  script_oid("1.3.6.1.4.1.25623.1.0.103742");
  script_version("2025-04-04T15:42:05+0000");
  script_tag(name:"last_modification", value:"2025-04-04 15:42:05 +0000 (Fri, 04 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-06-20 11:43:29 +0200 (Thu, 20 Jun 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("GLPI Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of GLPI.");

  script_xref(name:"URL", value:"https://glpi-project.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/glpi", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/";
  res = http_get_cache(port: port, item: url);

  #nb: Some instances return an empty response for "/", but yield the content on "/index.php"
  if (!res) {
    url = dir + "/index.php";

    res = http_get_cache(port: port, item: url);
    if (!res)
      continue;
  }

  # nb: Some versions had that "fi" typo in the title.
  if ((res =~ "<title>GLPI - Auth?enti" || res =~ "<title>Auth?enti[^ ]+ - GLPI</title>" ||
      "logo-GLPI" >< res) &&
      (res =~ "Powered By (Indepnet|Teclib)" || "_glpi_csrf_token" >< res)) {
    version = "unknown";
    conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # >GLPI version 0.90.3 Copyright (C) 2015 By Teclib
    vers = eregmatch(pattern: "GLPI version ([0-9.]+)", string: res, icase: TRUE);
    if (!isnull(vers[1])) {
       version = vers[1];
    } else {
      # src="/glpi/lib/fuzzy/fuzzy-min.js?v=9.4.3"
      vers = eregmatch(string: res, pattern: 'src="[^"]+?v=([0-9.]+)"', icase: TRUE);
      if(!isnull( vers[1])) {
        version = vers[1];
      } else {
        url = dir + "/CHANGELOG.md";

        res = http_get_cache(port: port, item: url);

        # ## [10.0.18] 2025-02-12
        vers = eregmatch(pattern: "##\s+\[([0-9.]+)\]\s+[0-9-]+", string: res);
        if (!isnull(vers[1])) {
          version = vers[1];
          conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        } else {
          url = dir + "/public/lib/photoswipe.js.map";

          req = http_get(port: port, item: url);
          res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

          # /tmp/glpi-10.0.18/glpi/node_modules/
          vers = eregmatch(pattern: "/tmp/glpi\-([0-9.]+)/", string: res);
          if (!isnull(vers[1])) {
            version = vers[1];
            conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
          }
        }
      }
    }

    set_kb_item(name: "glpi/detected", value: TRUE);
    set_kb_item(name: "glpi/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:glpi-project:glpi:");
    if (!cpe)
      cpe = "cpe:/a:glpi-project:glpi";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "GLPI", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: conclUrl),
                port: port);

    exit(0);
  }
}

exit(0);
