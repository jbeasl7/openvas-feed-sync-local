# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100382");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-12-08 22:02:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("phpShop Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of phpShop.");

  script_xref(name:"URL", value:"https://phpshop.sourceforge.net/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/shop", "/phpshop", http_cgi_dirs(port: port))) {
  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache(item: url, port: port);
  if (!res)
    continue;

  if (egrep(pattern: "Powered by <a [^>]+>phpShop", string: res, icase: TRUE)) {
    version = "unknown";

    vers = eregmatch(string: res, pattern: "Powered by <a [^>]+>phpShop</a> ([0-9.]+)", icase: TRUE);
    if (!isnull(vers[1])) {
      version = vers[1];

      # downloaded version 0.8.1 but /WEB-INF/etc/config.php contains "define("PHPSHOP_VERSION","0.8.0");".
      # In README.txt -> "phpShop version 0.8.1". So if version is 0.8.0 check README.txt to make sure we
      # got the real version.
      if (version_is_equal(version: version, test_version: "0.8.0")) {
        url = dir + "/README.txt";
        req = http_get(item: url, port: port);
        res = http_keepalive_send_recv(port: port, data: res, bodyonly: FALSE);

        vers = eregmatch(string: res, pattern: "phpShop version ([0-9.]+)");
        if (!isnull(vers[1]) && vers[1] != version) {
          version = vers[1];
          concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
        }
      }
    }

    set_kb_item(name: "phpshop/detected", value: TRUE);
    set_kb_item(name: "phpshop/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:edikon:phpshop:");
    if (!cpe)
      cpe = "cpe:/a:edikon:phpshop";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "phpShop", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: concUrl),
                port: port);

    exit(0);
  }
}

exit(0);
