# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100823");
  script_version("2024-07-12T15:38:44+0000");
  script_tag(name:"last_modification", value:"2024-07-12 15:38:44 +0000 (Fri, 12 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-09-24 14:46:08 +0200 (Fri, 24 Sep 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("EGroupware Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of EGroupware.");

  script_xref(name:"URL", value:"https://www.egroupware.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/egw", "/egroupware", "/groupware", "/eGroupware/egroupware", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/login.php";

  res = http_get_cache(port: port, item: url);
  if (!res)
    continue;

  if (res =~ "^HTTP/1\.[01] 200" &&
      ("<title>eGroupWare [Login]</title>" >< res ||
       "<title>EGroupware [Login]</title>" >< res ||
       '<meta name="author" content="EGroupware' >< res ||
       '<meta name="keywords" content="EGroupware' >< res ||
       '<meta name="description" content="EGroupware' >< res ||
       '<meta name="copyright" content="EGroupware' >< res ||
       ('<div id="divLogo"><a href=' >< res && "<!-- BEGIN registration -->" >< res &&
        "<!-- END registration -->" >< res))) {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    url = dir + "/package.json";
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);

    # "version": "23.1.20240624",
    # "version": "21.1.20210316",
    # "version": "19.1.001",
    vers = eregmatch(pattern: '"version"\\s*:\\s*"([0-9.]+)"', string: res);
    if (isnull(vers[1])) {
      url = dir + "/setup/index.php";

      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

      # <div id="divPoweredBy"><br /><span>&nbsp;<a class="copyright" href="http://www.egroupware.org/">eGroupWare</a> version 1.4.004 </span></div>
      # <div id="divPoweredBy"><br /><span>&nbsp;<a class="copyright" href="http://www.egroupware.org/">eGroupWare</a> version 1.8.007 </span></div>
      # <div id="divPoweredBy"><br /><span>&nbsp;<a class="copyright" href="http://www.egroupware.org/">EGroupware</a> Version 17.1 </span></div>
      vers = eregmatch(string: res, pattern: "version ([0-9.]+)", icase: TRUE);
      if (isnull(vers[1])) {
        url = dir + "/status.php";

        req = http_get(port: port, item: url);
        res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

        # {"installed":"true","version":"4.80.1","versionstring":"EGroupware 23.1.005","edition":""}
        # {"installed":"true","version":"4.80.1","versionstring":"EGroupware 21.1.001","edition":""}
        # {"installed":"true","version":"4.80.1","versionstring":"EGroupware 17.1.007","edition":""}
        # {"installed":"true","version":"4.80.1","versionstring":"EGroupware 17.1","edition":""}
        # {"installed":"true","version":"4.80.1","versionstring":"EGroupware 1.8.007","edition":""}
        vers = eregmatch(string: res, pattern: 'versionstring"\\s*:\\s*"EGroupware ([0-9.]+)"', icase: TRUE);
      }
    }

    if (!isnull(vers[1])) {
      version = vers[1];
      conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }

    # EGroupware's version has been unified since 16.1 (no more differences between various editions)
    # The patterns above don't match to the exact versions that are being declared vulnerable in a
    # vulnerability report
    if (version == "unknown" || version =~ "^16") {
      url = dir + "/doc/rpm-build/debian.changes";

      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

      # egroupware-epl (17.1.20180209)
      vers = eregmatch(pattern: "egroupware-epl \(([0-9.]+)\)", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    set_kb_item(name: "egroupware/detected", value: TRUE);
    set_kb_item(name: "egroupware/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:egroupware:egroupware:");
    if (!cpe)
      cpe = "cpe:/a:egroupware:egroupware";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "EGroupware", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
