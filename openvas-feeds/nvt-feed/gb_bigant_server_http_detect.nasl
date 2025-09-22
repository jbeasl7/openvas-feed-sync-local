# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100280");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("BigAnt Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of BigAnt Server.");

  script_add_preference(name:"BigAnt Server Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"BigAnt Server Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://www.bigantsoft.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8000);

url = "/index.php/Home/login/index.html";

res = http_get_cache(port: port, item: url);

if ("<title>BigAnt Admin" >< res || 'href="">BigAnt Admin' >< res ||
    egrep(pattern: "Server\s*:\s*AntServer", string: res, icase: TRUE)) {
  version = "unknown";
  location = "/";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "bigant/server/detected", value: TRUE);
  set_kb_item(name: "bigant/server/http/detected", value: TRUE);

  user = script_get_preference("BigAnt Server Web UI Username", id: 1);
  pass = script_get_preference("BigAnt Server Web UI Password", id: 2);

  if (!user && !pass) {
    extra = "Note: No username and password for web authentication were provided. Please pass these for version extraction.";
  } else if (!user && pass) {
    extra = "Note: Password for web authentication was provided but Username is missing.";
  } else if (user && !pass) {
    extra = "Note: Username for web authentication was provided but Password is missing.";
  } else if (user && pass) {
    url = "/index.php/Home/Login/login_post.html";

    headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                         "X-Requested-With", "XMLHttpRequest");

    data = "saas=default&account=" + user + "&password=" + base64(str: pass) + "&app=&submit=";

    req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
    res = http_keepalive_send_recv(port: port, data: req);

    FAILED = FALSE;

    if (res !~ "^HTTP/1\.[01] 200" || "Account or Password Error" >< res) {
      # nb: Older versions don't expect base64 encoded password
      data = "saas=default&account=" + user + "&password=" + pass + "&app=&submit=";

      req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      if (res !~ "^HTTP/1\.[01] 200" || "Login Successfully!" >!< res)
        FAILED = TRUE;
    }

    if (!FAILED) {
      cookie = http_get_cookie_from_header(buf: res, pattern: "(PHPSESSID=[^; ]+)");
      if (cookie) {
        url = "/index.php/Admin/public/about";

        headers = make_array("Cookie", cookie);

        req = http_get_req(port: port, url: url, add_headers: headers);
        res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

        vers = eregmatch(pattern: ">Version</label>[^>]+>\s*([0-9.]+)", string: res);
        if (!isnull(vers[1])) {
          version = vers[1];
          conclUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        }
      } else {
        extra = "Note: Username and Password were provided but authentication failed.";
      }
    } else {
      extra = "Note: Username and Password were provided but authentication failed.";
    }
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:bigantsoft:bigant_server:");
  if (!cpe)
    cpe = "cpe:/a:bigantsoft:bigant_server";

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "BigAnt Server", version: version, install: location,
                                           cpe: cpe, concluded: vers[0], concludedUrl: conclUrl,
                                           extra: extra),
              port: port);
  exit(0);
}

exit(0);
