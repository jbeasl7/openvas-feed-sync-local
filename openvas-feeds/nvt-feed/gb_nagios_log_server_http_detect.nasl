# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107058");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-10-12 13:26:09 +0700 (Wed, 12 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Nagios Log Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Nagios Log Server.");

  script_xref(name:"URL", value:"https://www.nagios.com/products/nagios-log-server/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/nagioslogserver", "/nagios", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/login";

  res = http_get_cache(port: port, item: url);

  # nb: Can happen if the system is in a "down" / "waiting" state:
  # - 307 redirect
  # - "Waiting for Database Startup" string
  # - Location: /nagioslogserver/waiting
  #
  # or:
  #
  # - 307 redirect
  # - "Elasticsearch Database Offline" string
  # - Location: /nagioslogserver/down
  #
  # In both cases we can just request the "waiting" one and will get the same result for both
  #
  if (res =~ "^HTTP/1\.[01] 30." && egrep(string: res, pattern: "[Ll]ocation\s*:\s*" + dir + "/(down|waiting)", icase: FALSE)) {
    url = dir + "/waiting";
    res = http_get_cache(port: port, item: url);
  }

  if ("Nagios Log Server" >< res && "Nagios Enterprises" >< res && "var LS_USER_ID" >< res) {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    set_kb_item(name: "nagios/log_server/detected", value: TRUE);
    set_kb_item(name: "nagios/log_server/http/detected", value: TRUE);

    if ('<div class="demosplash"></div>' >< res)
      extra = "Demo Version";

    # var LS_VERSION = "2.0.4"
    # var LS_VERSION = "2.0.7";
    # var LS_VERSION = "2.1.13"
    # var LS_VERSION = "2024R1.1";
    # var LS_VERSION = "2024R1.3.1"
    vers = eregmatch(string: res, pattern: 'var LS_VERSION = "([0-9R.]+)"', icase: TRUE);
    if (isnull(vers[1]))
      vers = eregmatch(string: res, pattern: 'ver=([0-9R.]+)">');

    if (!isnull(vers[1]))
      version = vers[1];

    os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                           desc: "Nagios Log Server Detection (HTTP)");

    cpe = build_cpe(value: tolower(version), exp: "^([0-9r.]+)", base: "cpe:/a:nagios:log_server:");
    if (!cpe)
      cpe = "cpe:/a:nagios:log_server";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Nagios Log Server", version: version, install: install,
                                             cpe: cpe, concluded: vers[0], concludedUrl: conclUrl,
                                             extra: extra),
                port: port);
    exit(0);
  }
}

exit(0);
