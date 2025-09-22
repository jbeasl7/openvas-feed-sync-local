# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107062");
  script_version("2025-04-04T15:42:05+0000");
  script_tag(name:"last_modification", value:"2025-04-04 15:42:05 +0000 (Fri, 04 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-10-19 13:26:09 +0700 (Wed, 19 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Nagios Network Analyzer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Nagios Network Analyzer.");

  script_add_preference(name:"Nagios Network Analyzer API Access Token", value:"", type:"password", id:1);

  script_xref(name:"URL", value:"https://www.nagios.com/products/nagios-network-analyzer/");

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

foreach dir (make_list_unique("/", "/nagiosna", "/nagios", http_cgi_dirs(port: port))) {
  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";

  res = http_get_cache(port: port, item: url);

  if ("<title>Login &bull; Nagios Network Analyzer</title>" >!< res) {
    url = dir + "/login";

    res = http_get_cache(port: port, item: url);

    if ('"login-title">Log in to Nagios Network Analyzer' >!< res) {
      url = dir + "/index.php/login";

      res = http_get_cache(port: port, item: url);

      if ("<title>Login &bull; Nagios Network Analyzer</title>" >!< res || "nnalogo_small.png" >!< res)
        continue;
    }
  }

  version = "unknown";
  conclUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "nagios/network_analyzer/detected", value: TRUE);
  set_kb_item(name: "nagios/network_analyzer/http/detected", value: TRUE);

  vers = eregmatch(pattern: 'var NA_VERSION = "([0-9.]+)"', string: res, icase: TRUE);
  if (isnull(vers[1]))
    vers = eregmatch(pattern: 'ver=([0-9.]+)">', string: res);

  if (!isnull(vers[1]))
    vers = vers[1];

  if (version == "unknown") {
    token = script_get_preference("Nagios Network Analyzer API Access Token", id: 1);

    if (!token) {
      extra = "Note: No API Access Token for authentication was provided. Please pass this for version extraction.";
    } else {
      base_url = dir + "/index.php/api/system/get_product_info";

      url = base_url + "?token=" + token;

      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

      # {"product":"Nagios Network Analyzer","release":410,"version":"2024R2.1","version_major":"2024","version_minor":"2.1","build_id":"BUILD_ID"}
      vers = eregmatch(pattern: '"version"\\s*:\\s*"([0-9R.]+)"', string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        conclUrl += '\n  ' + http_report_vuln_url(port: port, url: base_url, url_only: TRUE);
      } else {
        extra = "Note: API Access Token was provided but authentication failed.";
      }
    }
  }

  cpe = build_cpe(value: tolower(version), exp: "^([0-9r.]+)", base: "cpe:/a:nagios:network_analyzer:");
  if (!cpe)
    cpe = "cpe:/a:nagios:network_analyzer";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app:"Nagios Network Analyzer", version:version, install: install,
                                           cpe: cpe, concluded: vers[0], concludedUrl: conclUrl,
                                           extra: extra),
              port:port);
  exit(0);
}

exit(0);
