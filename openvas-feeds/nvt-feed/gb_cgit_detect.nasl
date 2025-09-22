# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");
  script_oid("1.3.6.1.4.1.25623.1.0.103719");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-05-28 12:52:27 +0200 (Tue, 28 May 2013)");
  script_name("cgit Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Cgit.

The script sends a connection request to the server and attempts to
extract the version number from the reply.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);

foreach dir( make_list_unique( "/", "/cgit", "/git", http_cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if( buf =~ '<meta name=["\']generator["\'] content=["\']cgit' && "repository" >< buf )
 {

    vers = string("unknown");
    version = eregmatch(string: buf, pattern:'<meta name=["\']generator["\'] content=["\']cgit v([^"\']+)["\']/?>',icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/cgit"), value: string(vers," under ",install));
    set_kb_item(name:"cgit/installed", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:lars_hjemli:cgit:");
    if(isnull(cpe))
      cpe = 'cpe:/a:lars_hjemli:cgit';

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data: build_detection_report(app:"Cgit", version:vers, install:install, cpe:cpe, concluded: version[0]),
                port:port);

    lines = split(buf);
    foreach line(lines) {
      repo = eregmatch(pattern:"href='/[^>]+/'>([^<]+)</a>", string:line);
      if(!isnull(repo[1])) {
        set_kb_item(name:"cgit/repos", value:repo[1]);
      }
    }
    exit(0);
  }
}
exit(0);
