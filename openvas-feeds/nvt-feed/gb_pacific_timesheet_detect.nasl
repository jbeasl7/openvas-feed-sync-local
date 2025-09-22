# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800180");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Pacific Timesheet Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Pacific Timesheet.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", "/timesheet", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item: dir + "/about-show.do", port:port );

  if( res =~ "^HTTP/1\.[01] 200" && ">About Pacific Timesheet<" >< res ) {

    version = "unknown";

    ver = eregmatch( pattern:">Version ([0-9.]+) [Bb][Uu][Ii][Ll][Dd]"+
                                      " ([0-9]+)</", string:res );

    if( ! isnull( ver[1] ) && ! isnull( ver[2] ) )
      version = ver[1] + "." + ver[2];

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/" + port + "/pacificTimeSheet/Ver", value:tmp_version);
    set_kb_item(name:"pacifictimesheet/detected", value:TRUE);
    set_kb_item(name:"pacifictimesheet/http/detected", value:TRUE);

    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:pacifictimesheet:pacific_timesheet:" );
    if( ! cpe )
      cpe = "cpe:/a:pacifictimesheet:pacific_timesheet";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Pacific Timesheet",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
