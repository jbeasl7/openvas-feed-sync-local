# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103813");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-10-15 16:03:11 +0200 (Tue, 15 Oct 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ShoreTel ShoreWare Director Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

foreach dir( make_list_unique( "/ShoreWareDirector", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  url = dir + "/";
  buf = http_get_cache( item:url, port:port );
  if( ! buf ) continue;

  if("ShoreWare Director Login</TITLE>" >< buf && "ShoreTel, Inc" >< buf && "password" >< buf) {

    vers = 'unknown';

    version = eregmatch(pattern:"ShoreTel ([^& ]+)&nbsp", string:buf);
    if(!isnull(version[1])) vers = version[1];

    _build = eregmatch(pattern:"Build ([^<]+)<", string:buf);
    if(!isnull(_build[1])) build = _build[1];

    set_kb_item(name:"ShoreWare_Director/installed", value:TRUE);
    set_kb_item(name: string("www/", port, "/ShoreWare_Director/version"), value: string(vers," under ",install));
    set_kb_item(name: string("www/", port, "/ShoreWare_Director/build"), value: build);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:shoretel:shoreware_director:");
    if(isnull(cpe))
      cpe = 'cpe:/a:shoretel:shoreware_director';

    report_vers = vers;
    if(build) report_vers += ', Build: ' + build;

    register_product(cpe:cpe, location:install, port:port, service:"www");
    log_message(data: build_detection_report(app:"ShoreTel ShoreWare Director",version:report_vers,install:install,cpe:cpe,concluded: version[0]),
                port);
  }
}

exit(0);
