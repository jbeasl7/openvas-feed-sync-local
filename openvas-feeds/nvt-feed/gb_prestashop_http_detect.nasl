# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140721");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-01-23 13:49:11 +0700 (Tue, 23 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("PrestaShop Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of PrestaShop.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.prestashop.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/prestashop", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/error500.html";
  res = http_get_cache(port: port, item: url);

  if (res =~ 'content=".+PrestaShop"' && "contact us if the problem persists" >< res) {
    version = "unknown";

    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    url = dir + "/index.php";
    res = http_get_cache(port: port, item: url);

    vers = eregmatch(pattern: '<div class="text-center">([0-9.]+)<', string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    } else {
      # nb: This is often "blocked" on web server level via e.g. a .htaccess
      url = dir + "/docs/CHANGELOG.txt";
      res = http_get_cache(port: port, item: url);
      # #   v1.7.3.0 - (2018-02-28)
      vers = eregmatch(pattern: '#   v([0-9.]+) - [^\r\n]+', string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      } else {
        # Last resort as this is just the major version
        # PrestaShop 1.6
        url = dir + "/README.md";
        res = http_get_cache(port: port, item: url);
        vers = eregmatch(pattern: "version of PrestaShop ([0-9]\.[0-9])", string: res);
        if (!isnull(vers[1])) {
          version = vers[1];
          concUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        }
      }
    }

    set_kb_item(name: "prestashop/detected", value: TRUE);
    set_kb_item(name: "prestashop/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:prestashop:prestashop:");
    if (!cpe)
      cpe = "cpe:/a:prestashop:prestashop";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "PrestaShop", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);
