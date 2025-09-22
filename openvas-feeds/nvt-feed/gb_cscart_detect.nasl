# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106397");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-11-18 10:07:02 +0700 (Fri, 18 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("CS-Cart Detection");

  script_tag(name:"summary", value:"Detection of CS-Cart

  The script sends a connection request to the server and attempts to detect the presence of CS-Cart
and to extract its version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.cs-cart.com/");

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

foreach dir (make_list_unique("/", "/cart", "/cs", "/store", "/cscart", "/cs-cart", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/");

  if ("CS-Cart - Shopping Cart Software" >< res && "index.php?dispatch=" >< res) {
    version = "unknown";

    vers = eregmatch(pattern: "\.js\?ver=([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "cs_cart/version", value: version);
    }
    else {
      req = http_get(port: port, item: dir + "/changelog.txt");
      res = http_keepalive_send_recv(port: port, data: req);

      vers = eregmatch(pattern: "Version ([0-9.]+(\.?([a-zA-Z0-9]+))?),", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        set_kb_item(name: "cs_cart/version", value: version);
      }
    }

    set_kb_item(name: "cs_cart/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:cs-cart:cs-cart:");
    if (!cpe)
      cpe = 'cpe:/a:cs-cart:cs-cart';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "CS-Cart", version: version, install: install, cpe: cpe,
                                             concluded: vers[0]),
                port: port);
  }
}

exit(0);
