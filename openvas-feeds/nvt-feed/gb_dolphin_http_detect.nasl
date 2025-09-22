# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808217");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-06-06 15:55:57 +0530 (Mon, 06 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dolphin Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Dolphin.");

  script_xref(name:"URL", value:"https://www.boonex.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/dolph", "/dolphin", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url1 = dir + "/administration/profiles.php";
  res1 = http_get_cache(port: port, item: url1);

  url2 = dir + "/index.php";
  res2 = http_get_cache(port: port, item: url2);

  if (("Dolphin" >< res1 && "boonex" >< res1 && "<title>Login</title>" >< res1 &&
      'id="admin_username"' >< res1 && 'id="admin_password"' >< res1) ||
      (res2 =~ "^HTTP/1\.[01] 200" && ("dolRSSFeed();" >< res2 || "BxDolVoting.js" >< res2 || "dolTopMenu.js" >< res2))
     ) {
    version = "unknown";

    set_kb_item(name: "boonex/dolphin/detected", value: TRUE);
    set_kb_item(name: "boonex/dolphin/http/detected", value: TRUE);

    cpe = "cpe:/a:boonex:dolphin";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data:build_detection_report(app: "Dolphin", version: version, install: install, cpe: cpe),
                port: port);
    exit(0);
  }
}

exit(0);
