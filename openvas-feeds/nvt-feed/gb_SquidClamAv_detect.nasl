# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103566");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-09-17 11:48:05 +0200 (Mon, 17 Sep 2012)");
  script_name("SquidClamAv Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of SquidClamAv.

The script sends a connection request to the server and attempts to
extract the version number from the reply.");
  exit(0);
}

SCRIPT_DESC = "SquidClamAv Detection";

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + '/clwarn.cgi';
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( ! buf ) continue;

 if(egrep(pattern: "<title>SquidClamAv", string: buf, icase: TRUE) && "virus" >< buf)
 {
    vers = string("unknown");
    version = eregmatch(string: buf, pattern: "SquidClamAv ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/SquidClamAv"), value: string(vers," under ",install));
    set_kb_item(name:"SquidClamAv/installed",value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:darold:squidclamav:");
    if(isnull(cpe))
      cpe = 'cpe:/a:darold:squidclamav';

    register_product(cpe:cpe, location:install, port:port, service:"www");
    log_message(data: build_detection_report(app:"SquidClamAv", version:vers, install:install, cpe:cpe, concluded: version[0]),
                port:port);
    exit(0);

 }
}

exit(0);
