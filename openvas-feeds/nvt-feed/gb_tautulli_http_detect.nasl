# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143150");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-11-20 04:03:51 +0000 (Wed, 20 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Tautulli Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_mandatory_keys("CherryPy/banner");
  script_require_ports("Services/www", 8181);

  script_tag(name:"summary", value:"HTTP based detection of Tautulli.");

  script_xref(name:"URL", value:"https://tautulli.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8181);

banner = http_get_remote_headers(port: port);

if ("CherryPy" >!< banner)
  exit(0);

foreach dir (make_list_unique("/", "/tautulli", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/home";
  res = http_get_cache(port: port, item: url);

  if (res =~ "^HTTP/1\.[01] 303") {
    # Follow 2 redirects (logout/login)
    for (i = 0; i < 2; i++) {
      location = http_extract_location_from_redirect(port: port, data: res, current_dir: url);
      if (isnull(location))
        break;

      req = http_get(port: port, item: location);
      res = http_keepalive_send_recv(port: port, data: req);
      if (res !~ "HTTP/1\.[01] 303")
        break;
    }
  }

  if (res =~ "<title>Tautulli - (Home|Login)" && 'content="Tautulli"' >< res) {
    version = "unknown";
    conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    url = dir + "/settings";
    req = http_get(port: port, item: url);
    res2 = http_keepalive_send_recv(port: port, data: req);

    # <h3>Version v2.1.38 <small><a id="changelog-modal-link"
    vers = eregmatch(pattern: "Version v([0-9.]+)", string: res2);
    if (!isnull(vers[1])) {
      version = vers[1];
      conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    } else {
      # src="/tautulli/js/script.js?v2.15.3"
      vers = eregmatch(pattern: "script\.js\?v([0-9]+\.[0-9.]+)", string: res);
      if (!isnull(vers[1]))
        version = vers[1];
    }

    if ("http_plex_admin" >< res && "http_password" >< res)
      set_kb_item(name: "tautulli/" + port + "/noauth", value: TRUE);

    token = eregmatch(pattern: 'name="pms_token" value="([^"]+)"', string: res);
    if (!isnull(token[1]))
      set_kb_item(name: "tautulli/plex_token", value: token[1]);

    set_kb_item(name: "tautulli/detected", value: TRUE);
    set_kb_item(name: "tautulli/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:tautulli:tautulli:");
    if (!cpe)
      cpe = "cpe:/a:tautulli:tautulli";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Tautulli", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
