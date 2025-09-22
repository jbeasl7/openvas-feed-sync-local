# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113157");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-04-17 14:52:55 +0200 (Tue, 17 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IkiWiki Detection (Web UI)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of IkiWiki via Web UI.

  The script sends a GET request to the server and attempts to
  detect the presence of IkiWiki.");

  script_xref(name:"URL", value:"https://ikiwiki.info/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default: 80 );

foreach location ( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {

  if( location == "/" )
    dir = "";
  else
    dir = location;

  dir = dir + "/ikiwiki/";
  res = http_get_cache( port: port, item: dir );

  if( res =~ '<p>This wiki is powered by <a href="http://ikiwiki.info/">ikiwiki</a>\\.') {
    set_kb_item( name: "ikiwiki/detected", value: TRUE );
    set_kb_item( name: "ikiwiki/www/detected", value: TRUE );

    version = "unknown";
    vers = eregmatch( string: res, pattern: '\\(Currently running version ([0-9.]+)\\.\\)</p>' );

    if( vers[1] ) {
      version = vers[1];
      set_kb_item( name: "ikiwiki/webui/" + port + "/concluded", value: vers[0] );
    }

    set_kb_item( name: "ikiwiki/webui/port", value: port );
    set_kb_item( name: "ikiwiki/webui/" + port + "/version", value: version );
    set_kb_item( name: "ikiwiki/webui/" + port + "/location", value: location );
    break;
  }
}

exit( 0 );
