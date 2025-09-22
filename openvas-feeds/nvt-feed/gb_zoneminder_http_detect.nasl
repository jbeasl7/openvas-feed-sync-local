# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106520");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-01-17 13:28:38 +0700 (Tue, 17 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ZoneMinder Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ZoneMinder.");

  script_add_preference(name:"ZoneMinder Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"ZoneMinder Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://zoneminder.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/zm", "/zoneminder", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php";

  res = http_get_cache(port: port, item: url);

  if (("<h1>ZoneMinder Login</h1>" >< res || res =~ "<title>Zone[mM]inder - Console</title>" ||
       ">ZoneMinder<" >< res) && "var skinPath" >< res) {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    req = http_get(port: port, item: dir + "/index.php?view=version");
    res = http_keepalive_send_recv(port: port, data: req);

    vers = eregmatch(pattern: "ZoneMinder, v([0-9]+\.[0-9]+\.[0-9]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    } else {
      url = dir + "/api/host/getVersion.json";

      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req);

      # {"version":"1.36.4","apiversion":"2.0"}
      vers = eregmatch(pattern: '"version"\\s*:\\s*"([0-9.]+)', string: res);
      if (isnull(vers[1])) {
        user = script_get_preference("ZoneMinder Web UI Username", id: 1);
        pass = script_get_preference("ZoneMinder Web UI Password", id: 2);

        if (!user && !pass) {
          extra += '  Note: No username and password for web authentication were provided. These could be provided for extended version extraction.';
        } else if (!user && pass) {
          extra += '  Note: Password for web authentication was provided but username is missing. Please provide both.';
        } else if (user && !pass) {
          extra += '  Note: Username for web authentication was provided but password is missing. Please provide both.';
        } else if (user && pass) {
          headers = make_array("Content-Type", "application/x-www-form-urlencoded");

          data = "user=" + user + "&pass=" + pass;

          req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
          res = http_keepalive_send_recv(port: port, data: req);

          vers = eregmatch(pattern: '"version"\\s*:\\s*"([0-9.]+)', string: res);
          if (isnull(vers[1]))
            extra += '  Note: Username and password were provided but authentication failed.';
        }
      }

      if (!isnull(vers[1])) {
        version = vers[1];
        conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    set_kb_item(name: "zoneminder/detected", value: TRUE);
    set_kb_item(name: "zoneminder/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:zoneminder:zoneminder:");
    if (!cpe)
      cpe = "cpe:/a:zoneminder:zoneminder";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "ZoneMinder", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: conclUrl, extra: extra),
                port: port);
    exit(0);
  }
}

exit(0);
