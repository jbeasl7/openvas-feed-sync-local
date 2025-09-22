# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103106");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-03-04 13:25:07 +0100 (Fri, 04 Mar 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("phpWebSite Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of phpWebSite.");

  script_xref(name:"URL", value:"http://phpwebsite.appstate.edu/");

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

foreach dir (make_list_unique("/phpwebsite", "/cms", http_cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php?module=users&action=user&command=login_page";

  res = http_get_cache(port: port, item: url);

  if ('<meta name="generator" content="phpWebSite" />' >< res &&
      "User_Login_Main_phpws_username" >< res) {
    version = "unknown";

    set_kb_item(name: "phpwebsite/detected", value: TRUE);
    set_kb_item(name: "phpwebsite/http/detected", value: TRUE);

    cpe = "cpe:/a:phpwebsite:phpwebsite";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(build_detection_report(app: "phpWebSite", version: version, install: install, cpe: cpe,
                                       concludedUrl: http_report_vuln_url(port: port, url: url, url_only: TRUE)),
                port: port);
    exit(0);
  }
}

exit(0);
