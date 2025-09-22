# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100322");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-10-29 12:31:54 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Basic Analysis and Security Engine Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running Basic Analysis and Security Engine (BASE). BASE provides
  a web front-end to query and analyze the alerts coming from a SNORT IDS system.");

  script_xref(name:"URL", value:"https://sourceforge.net/projects/secureideas/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/base", "/snort/base", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/";
  buf = http_get_cache(port: port, item: url);

  if(egrep(pattern: "<title>Basic Analysis and Security Engine \(BASE\)", string: buf, icase: TRUE) ) {
    vers = "unknown";

    version = eregmatch(string: buf, pattern: "BASE[)</a>]* ([0-9.]+)",icase:TRUE);

    if (!isnull(version[1]))
      vers=chomp(version[1]);

    tmp_version = string(vers," under ",install);
    set_kb_item(name: string("www/", port, "/BASE"), value: tmp_version);
    set_kb_item(name:"BASE/installed",value:TRUE);

    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:secureideas:base:");
    if (!cpe)
      cpe = 'cpe:/a:secureideas:base';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Basic Analysis and Security Engine (BASE)", version: vers,
                                             install: install, cpe: cpe, concluded: version[0]),
                port: port);
    exit(0);
  }
}

exit(0);
