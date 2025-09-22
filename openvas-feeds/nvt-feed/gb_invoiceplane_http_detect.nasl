# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106829");
  script_version("2025-04-07T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-04-07 05:39:52 +0000 (Mon, 07 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-05-24 13:09:38 +0700 (Wed, 24 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("InvoicePlane Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of InvoicePlane.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_add_preference(name:"InvoicePlane Login Email", value:"", type:"entry", id:1);
  script_add_preference(name:"InvoicePlane Login Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://invoiceplane.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("url_func.inc");

port = http_get_port(default: 80);

url = "/index.php/sessions/login";

res = http_get_cache(port: port, item: url);

if ("InvoicePlane    </title>" >!< res && '<div class="alert alert-danger no-margin">' >!< res) {
  url = "/invoiceplane/sessions/login";

  res = http_get_cache(port: port, item: url);

  if ("<title>InvoicePlane</title>" >< res && "invoiceplane/sessions/passwordreset" >< res)
    install = "/invoiceplane";
  else
    exit(0);
}
else
  install = "/";

if (install == "/")
  dir = "";
else
  dir = install;

version = "unknown";

conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
url2 = dir + "/README.md";
req = http_get(port: port, item: url2);
res2 = http_keepalive_send_recv(port: port, data: req);

vers = eregmatch(pattern: "#### _Version ([0-9.]+)", string: res2);
if (!isnull(vers[1])) {
  version = vers[1];
  conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);
  concl = "  " + vers[0];
}

if (version == "unknown") {
  user = script_get_preference("InvoicePlane Login Email", id: 1);
  pass = script_get_preference("InvoicePlane Login Password", id: 2);

  if (!user && !pass) {
    extra = "Note: No email and password credentials for web authentication were provided. Please provide these for version extraction.";
  } else if (!user && pass) {
    extra = "Note: Password for web authentication was provided but Login Email is missing.";
  } else if (user && !pass) {
    extra = "Note: Email for web authentication was provided but Password is missing.";
  } else if (user && pass) {
    csrf_cookie = http_get_cookie_from_header(buf: res, pattern: "(ip_csrf_cookie[^;]+)");
    session_cookie = http_get_cookie_from_header(buf: res, pattern: "(ip_session[^;]+)");

    if (csrf_cookie) {
      cookie_val = eregmatch(pattern: "ip_csrf_cookie=([a-z0-9]+)", string: csrf_cookie);
      full_cookie = csrf_cookie + ";";
      if (session_cookie)
        full_cookie += session_cookie + ";";

      if (cookie_val[1]) {
        # _ip_csrf=8eb3e77ac7248b210642002102195bf5&email=test%40test.net&password=Test%21&btn_login=true
        post_data = "_ip_csrf=" + cookie_val[1] + "&email=" + urlencode(str: user, special_char_set: "*-_.") + "&password=" + urlencode(str: pass, uppercase: TRUE, special_char_set: "*-_.") + "&btn_login=true";

        headers = make_array("Cookie", full_cookie,
                             "Content-Type", "application/x-www-form-urlencoded");
        req = http_post_put_req(port: port, url: url, data: post_data, add_headers: headers);
        res = http_keepalive_send_recv(port: port, data: req);

        if (res && res =~ "^HTTP/(1\.[01]|2) (2[02]0|303)" && "index.php/dashboard" >< res) {
          csrf_cookie = http_get_cookie_from_header(buf: res, pattern: "(ip_csrf_cookie[^;]+)");
          full_cookie = csrf_cookie + ";";
          if (session_cookie)
            full_cookie += session_cookie + ";";
          url = "/index.php/settings";
          headers = make_array("Cookie", full_cookie);
          req = http_get_req(port: port, url: url, add_headers: headers);
          res = http_keepalive_send_recv(port: port, data: req);

          #        var ip_version = "1.6.2";
          vers = eregmatch(pattern: 'var ip_version\\s*=\\s*"([.0-9]+)"', string: res);
          if (!isnull(vers[1])) {
            version = vers[1];
            concl = "  " + vers[0];
            conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
          }
        } else {
          extra = "Note: Username and password were provided but authentication failed.";
        }
      }

    }

  }
}

set_kb_item(name: "invoiceplane/detected", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:invoiceplane:invoiceplane:");
if (!cpe)
  cpe = "cpe:/a:invoiceplane:invoiceplane";

register_product(cpe: cpe, location: install, port: port, service: "www");

log_message(data: build_detection_report(app: "InvoicePlane", version: version, install: install, cpe: cpe,
                                         concluded: concl, concludedUrl: conclUrl, extra: extra),
            port: port);

exit(0);
