# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812511");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-02-08 11:46:24 +0530 (Thu, 08 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Odoo Business Management Software Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8069);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Odoo business management
  software.");

  script_add_preference(name:"Odoo Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Odoo Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://www.odoo.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("url_func.inc");

port = http_get_port(default: 8069);

foreach dir (make_list_unique("/", "/Odoo", "/odoo_cms", "/odoo_cmr", "/CMR", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  url = dir + "/web/login";

  res = http_get_cache(port: port, item: url);

  if (("Log in with Odoo.com" >!< res && "<title>Odoo</title>" >!< res) ||
      (res !~ '(P|p)owered by.*>Odoo' && 'content="Odoo' >!< res)) {
    url = dir + "/web/database/selector";

    res = http_get_cache(port: port, item: url);

    if ("<title>Odoo</title>" >!< res || ">Backup Database<" >!< res)
      continue;

    # href="/web?db=Test">
    db = eregmatch(pattern: 'web\\?db=([^"]+)"', string: res);
    if (!isnull(db[1]))
      db = db[1];
  }

  version = "unknown";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "odoo/detected", value: TRUE);
  set_kb_item(name: "odoo/http/detected", value: TRUE);

  user = script_get_preference("Odoo Web UI Username", id: 1);
  pass = script_get_preference("Odoo Web UI Password", id: 2);

  if (!user && !pass) {
    extra = "Note: No username and password for web authentication were provided. Please provide these for version extraction.";
  } else if (!user && pass) {
    extra = "Note: Password for web authentication was provided but Username is missing.";
  } else if (user && !pass) {
    extra = "Note: Username for web authentication was provided but Password is missing.";
  } else if (user && pass) {
    url = dir + "/web/login";
    if (db)
      url += "?db=" + db;

    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);

    csrf_token = eregmatch(pattern: 'csrf_token\\s*:\\s*"([^"]+)"', string: res);
    cookie = http_get_cookie_from_header(buf: res, pattern: "(session_id=[^; ]+)");
    if (!isnull(csrf_token[1]) && cookie) {
      csrf_token = csrf_token[1];

      headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                           "Cookie", cookie);

      user = urlencode(str: user);

      data = "csrf_token=" + csrf_token + "&login=" + user + "&password=" + pass +
             "&type=password";

      req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      cookie = http_get_cookie_from_header(buf: res, pattern: "(session_id=[^; ]+)");
      loc = http_extract_location_from_redirect(port: port, data: res, current_dir: install);

      if (res =~ "^HTTP/1\.[01] 303" && cookie && loc) {
        headers = make_array("Cookie", cookie);

        url = loc + "/settings";

        req = http_get_req(port: port, url: url, add_headers: headers);
        res = http_keepalive_send_recv(port: port, data: req);

        # "server_version": "18.0-20250218"
        vers = eregmatch(pattern: '"server_version"\\s*:\\s*"([0-9.-]+)"', string: res);
        if (!isnull(vers[1])) {
          version = vers[1];
          conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        }

        # src="/web/assets/127eab9/web.assets_web.min.js"
        asset = eregmatch(pattern: 'src="(.*/web/assets/.*/web.assets_web\\.min\\.js)"', string: res);
        if (!isnull(asset[1])) {
          req = http_get_req(port: port, url: asset[1], add_headers: headers);
          # nb: This file is quite big so can't use http_keepalive_send_recv()
          res = http_send_recv(port: port, data: req);

          # Odoo <t t-esc="serverVersion"/>
          # Community Edition)
          ed = eregmatch(pattern: "(Community|Enterprise) Edition", string: res);
          if (!isnull(ed[1])) {
            edition = ed[1];
            set_kb_item(name: "odoo/edition", value: tolower(edition));
            conclUrl += '\n  ' + http_report_vuln_url(port: port, url: asset[1], url_only: TRUE);
            edition += " Edition";
          }
        }
      } else {
        extra = "Note: Username and Password were provided but authentication failed.";
      }
    } else {
      extra = "Note: Username and Password were provided but authentication failed.";
    }
  }

  cpe = build_cpe(value: version, exp: "^([0-9.-]+)", base: "cpe:/a:odoo:odoo:");
  if (!cpe)
    cpe = "cpe:/a:odoo:odoo";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Odoo " + edition, version: version, install: install, cpe: cpe,
                                           concluded: vers[0], concludedUrl: conclUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
