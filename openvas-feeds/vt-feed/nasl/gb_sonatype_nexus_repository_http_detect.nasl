# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805324");
  script_version("2026-08-11T05:56:26+0000");
  script_tag(name:"last_modification", value:"2026-08-11 05:56:26 +0000 (Tue, 11 Aug 2026)");
  script_tag(name:"creation_date", value:"2015-01-20 13:00:12 +0530 (Tue, 20 Jan 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sonatype Nexus Repository Manager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Sonatype Nexus Repository Manager.");

  script_xref(name:"URL", value:"https://www.sonatype.com/products/sonatype-nexus-repository");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

base_cpe = "cpe:/a:sonatype:nexus_repository_manager";

port = http_get_port(default: 8081);

banner = http_get_remote_headers(port: port);

if (banner && egrep(pattern: "[Ss]erver: Nexus", string: banner, icase: FALSE)) {
  version = "unknown";
  install = "/";
  conclUrl = "  " + http_report_vuln_url(port: port, url: install, url_only: TRUE);

  # Server: Nexus/3.0.2-02 (OSS)
  # Server: Nexus/3.17.0-01 (OSS)
  # Server: Nexus/2.14.1-01
  # Server: Nexus/3.89.0-09 (COMMUNITY)
  vers = eregmatch(pattern: 'Server\\s*:\\s*Nexus.([0-9.-]+)[^\r\n]*', string: banner, icase: TRUE);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name:"sonatype/nexus_repository/detected", value: TRUE);
  set_kb_item(name:"sonatype/nexus_repository/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "([0-9.-]+)", base: base_cpe + ":");
  if (!cpe)
    cpe = base_cpe;

  register_product(cpe: cpe, location: install, port:port, service:"www");

  log_message(data:build_detection_report(app: "Sonatype Nexus Repository Manager", version: version,
                                          install: install, cpe: cpe, concluded: vers[0],
                                          concludedUrl: conclUrl),
              port: port);
  exit(0);
}

foreach dir (make_list_unique("/", "/nexus", http_cgi_dirs(port: port))) {
  install = dir;
  if(dir == "/")
    dir = "";

  url = dir + "/#welcome";

  res = http_get_cache(port: port, item: url);

  if (res && (">Sonatype Nexus<" >< res || res =~ ">Sonatype Nexus (Professional|Repository)<")) {
    version = "unknown";
    found = TRUE;
    conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # nb: Not sure if this is a typo
    vers = eregmatch(pattern: "verssion=([0-9.-]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
    } else {
      # app.js?_v=3.68.1-02
      vers = eregmatch(pattern: "_v=([0-9.-]+)", string: res);
      if (!isnull(vers[1]))
        version = vers[1];
    }
  } else {
    url = dir + "/#browse/welcome";

    res = http_get_cache(port: port, item: url);

    if ("Nexus Repository Manager" >< res) {
      version = "unknown";
      found = TRUE;
      conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

      # loading-prod.css?_v=3.15.2-01">
      vers = eregmatch(pattern: "_v=([0-9.-]+)", string: res);
      if (!isnull(vers[1]))
        version = vers[1];
    }
  }

  if (found) {
    set_kb_item(name:"sonatype/nexus_repository/detected", value: TRUE);
    set_kb_item(name:"sonatype/nexus_repository/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "([0-9.-]+)", base: base_cpe + ":");
    if (!cpe)
      cpe = base_cpe;

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Sonatype Nexus Repository Manager", version: version,
                                             install: install, cpe: cpe, concluded: vers[0],
                                             concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
