# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144235");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2020-07-15 03:40:31 +0000 (Wed, 15 Jul 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Guacamole Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Apache Guacamole.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://guacamole.apache.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", "/guacamole", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/";
  res = http_get_cache(port: port, item: url);
  if (!res)
    continue;

  if ("<title>Guacamole" >< res || "images/guacamole-logo-64.png" >< res || "guac-ui.js" >< res ||
      "<guac-notification notification" >< res) {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # <div id="version"> Guacamole 0.9.2 </div>
    vers = eregmatch(pattern: '<div id="version">\\s+Guacamole ([0-9.]+)', string: res);
    if (!isnull(vers[1]))
      version = vers[1];

    if (version == "unknown") {
      # src="app.js?v=0.9.12-incubating"
      # nb: Newer version (1.4.0+) are not exposing their version like this anymore. These are using
      # something like e.g. the following instead:
      # src="app.js?b=20220215005227"
      vers = eregmatch(pattern: "\.js\?v=([0-9]+\.[0-9.]+)", string: res);
      if (!isnull(vers[1]))
        version = vers[1];
    }

    if (version == "unknown") {
      url = dir + "/translations/en.json";
      res = http_get_cache(port: port, item: url);
      if (res && res =~ "^HTTP/1\.[01] 200") {
        # "VERSION":"1.4.0",
        # "VERSION":"1.5.2",
        vers = eregmatch(pattern: '"VERSION"\\s*:\\s*"([0-9.]{3,})[^"]*",', string: res, icase: FALSE);
        if (!isnull(vers[1])) {
          version = vers[1];
          conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
        }
      }
    }

    set_kb_item(name: "apache/guacamole/detected", value: TRUE);
    set_kb_item(name: "apache/guacamole/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:guacamole:");
    if (!cpe)
      cpe = "cpe:/a:apache:guacamole";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Apache Guacamole", version: version, install: install,
                                             cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
