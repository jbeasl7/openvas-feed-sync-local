# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100001");
  script_version("2024-08-02T15:38:45+0000");
  script_tag(name:"last_modification", value:"2024-08-02 15:38:45 +0000 (Fri, 02 Aug 2024)");
  script_tag(name:"creation_date", value:"2009-02-26 04:52:45 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("osCommerce Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of osCommerce.");

  script_add_preference(name:"osCommerce Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"osCommerce Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://www.oscommerce.com/");

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

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/osc", "/oscommerce", "/store", "/catalog", "/shop", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache(port: port, item: url);

  if (!res)
    continue;

  if (res !~ "^HTTP/1\.[01] 200" ||
      ("osCsid=" >!< res && !egrep(string: res, pattern: "Powered by.+osCommerce", icase: FALSE) &&
       'content="osCommerce Online Merchant' >!< res)) {
    url = dir + "/admin/login";
    res = http_get_cache(port: port, item: url);

    if (res !~ "^HTTP/1\.[01] 200" ||
        ('content="osCommerce Online Merchant' >!< res && ">osCommerce is provided under" >!< res)) {
      url = dir + "/ssl_check.php";
      res = http_get_cache(item: url, port: port);
      # In English:
      # We validate the SSL Session ID automatically generated
      # *snip*
      # We have detected that your browser has generated a different SSL Session ID
      #
      # or in German:
      # Die von Ihrem Browser erzeugte SSL-Session ID
      # *snip*
      # Unsere Sicherheits&uuml;berpr&uuml;fung hat ergeben, dass der Ihrerseits verwendete Browser die SSL-Session-Id
      if (res !~ "^HTTP/1\.[01] 200" ||
          !eregmatch(string: res, pattern: "SSL.+I[Dd].+SSL.+I[Dd]", icase: FALSE))
        continue;
    }
  }

  version = "unknown";

  set_kb_item(name: "oscommerce/detected", value: TRUE);
  set_kb_item(name: "oscommerce/http/detected", value: TRUE);

  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  url = dir + "/admin/login.php";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  cookie = http_get_cookie_from_header(buf: res);
  if (cookie && res =~ "^HTTP/1\.[01] 302") {
    headers = make_array("Cookie", cookie);
    req = http_get_req(port: port, url: url, add_headers: headers);
    res = http_keepalive_send_recv(port: port, data: req);
  }

  # alt="osCommerce Online Merchant v2.3.4.1
  vers = eregmatch(pattern: "osCommerce Online Merchant v([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  if (version == "unknown") {
    user = script_get_preference("osCommerce Web UI Username", id: 1);
    pass = script_get_preference("osCommerce Web UI Password", id: 2);

    if (!user && !pass) {
      extra += "No username and password for web authentication were provided. These could be provided for extended version extraction.";
    } else if (!user && pass) {
      extra += "Password for web authentication was provided but username is missing. Please provide both.";
    } else if (user && !pass) {
      extra += "Username for web authentication was provided but password is missing. Please provide both.";
    } else if (user && pass) {
      url = dir + "/admin/login";

      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req);

      cookie1 = http_get_cookie_from_header(buf: res, pattern: "(_csrf=[^;]+)");
      cookie2 = http_get_cookie_from_header(buf: res, pattern: "(tlAdminID=[^;]+)");
      # name="_csrf" value="<redacted>">
      csrf = eregmatch(pattern: 'name="_csrf"\\s*value="([^"]+)"', string: res);

      if (cookie1 && cookie2 && !isnull(csrf[1])) {
        url = dir + "/admin/login?action=process";

        headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                             "Cookie", cookie1 + "; " + cookie2);

        data = "_csrf=" + urlencode(str: csrf[1]) + "&email_address=" + urlencode(str: user) + "&password=" +
               urlencode(str: pass, special_char_set: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");

        req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
        res = http_keepalive_send_recv(port: port, data: req);

        if (res =~ "^HTTP/1\.[01] 302" && res =~ "set-cookie\s*:\s*tlAdminID=[a-zA-Z0-9]+;") {
          cookie = http_get_cookie_from_header(buf: res, pattern: "(tlAdminID=[^;]+)");

          url = dir + "/admin/install/updates";

          headers = make_array("Cookie", cookie1 + "; " + cookie);

          req = http_get_req(port: port, url: url, add_headers: headers);
          res = http_keepalive_send_recv(port: port, data: req);

          # Current version 4.13.60076
          vers = eregmatch(pattern: "Current version\s+([0-9.]+)", string: res);
          if (!isnull(vers[1])) {
            version = vers[1];
            concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
          }
        } else {
          extra += "Username and password were provided but authentication failed.";
        }
      } else {
        extra += "Username and password were provided but something went wrong.";
      }
    }
  }


  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:oscommerce:oscommerce:");
  if (!cpe)
    cpe = "cpe:/a:oscommerce:oscommerce";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "osCommerce", version: version, install: install,
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
