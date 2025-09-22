# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100217");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-06-01 13:46:24 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("phpBugTracker Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of phpBugTracker.");

  script_xref(name:"URL", value:"http://phpbt.sourceforge.net/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/phpbt", "/bugtracker", "/bugs", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  res = http_get_cache( item: dir + "/index.php", port:port );

  if( egrep( pattern:"<title>phpBugTracker - Home</title>", string:res, icase:TRUE ) ||
      egrep( pattern:"<title>phpBugTracker Login</title>", string:res, icase:TRUE ) ||
      egrep( pattern:"<title>Home - phpBugTracker</title>", string:res, icase:TRUE ) ||
      "<b>phpBugTracker</b>" >< res ) {

    version = "unknown";

    url = dir + "/CHANGELOG";

    res = http_get_cache( item:url, port:port );

    # -- 0.9.1 -- 4 Jan 2003
    ver = eregmatch( string:res, pattern:"-- ([0-9.]+)" );
    if ( ! isnull( ver[1] ) ) {
      version = ver[1];
      concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    set_kb_item( name:"phpbugtracker/detected", value:TRUE );
    set_kb_item( name:"phpbugtracker/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+?)", base:"cpe:/a:benjamin_curtis:phpbugtracker:" );
    if( ! cpe )
      cpe = "cpe:/a:benjamin_curtis:phpbugtracker";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"phpBugTracker", version:version, install:install,
                                              cpe:cpe, concluded:ver[0], concludedUrl:concUrl ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
