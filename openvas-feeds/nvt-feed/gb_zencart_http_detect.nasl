# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146890");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2021-10-12 13:10:00 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Zen Cart Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Zen Cart.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.zen-cart.com/");

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

foreach dir (make_list_unique("/", "/shop", "/cart", "/zen-cart", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/index.php");
  res2 = http_get_cache(port: port, item: dir + "/admin/login.php");

  if (('content="The Zen Cart' >< res && 'content="shopping cart program by Zen Cart' >< res) ||
      egrep(pattern: "Powered by.+Zen Cart<", string: res, icase: FALSE) ||
      res2 =~ "<title>Zen Cart!</title>") {
    version = "unknown";

    url = dir + "/README.md";
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);

    # Zen Cart&reg; v1.5.5f
    vers = eregmatch(pattern: "Zen Cart&reg; v([0-9a-z.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }

    set_kb_item(name: "zen_cart/detected", value: TRUE);
    set_kb_item(name: "zen_cart/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:zen-cart:zen_cart:");
    if (!cpe)
      cpe = "cpe:/a:zen-cart:zen_cart";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Zen Cart", version: version, install: install,
                                             cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);
