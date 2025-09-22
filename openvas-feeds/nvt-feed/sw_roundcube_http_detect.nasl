# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# SPDX-FileCopyrightText: Improved code and additional detection routines since 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111027");
  script_version("2025-06-05T05:40:56+0000");
  script_tag(name:"last_modification", value:"2025-06-05 05:40:56 +0000 (Thu, 05 Jun 2025)");
  script_tag(name:"creation_date", value:"2015-08-21 16:00:00 +0200 (Fri, 21 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Roundcube Webmail Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://roundcube.net");

  script_tag(name:"summary", value:"HTTP based detection of Roundcube Webmail.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/roundcube", "/webmail", "/mail", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";
  buf = http_get_cache( item:url, port:port );
  if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
    continue;

  # <meta http-equiv="content-type" content="text/html; charset=UTF-8"><title>Roundcube Webmail :: Welcome to Roundcube Webmail</title>
  # <title>Roundcube Webmail :: </title>
  # <title>RoundCube Webmail :: Welcome to RoundCube Webmail</title>
  # <meta http-equiv="content-type" content="text/html; charset=UTF-8"><title>$somestring: Roundcube Webmail :: Welcome to $somestring: Roundcube Webmail</title>
  # <title>Roundcube Webmail :: ERROR</title>
  #
  # nb: If required in the future "Set-Cookie: roundcube_sessid=" could be also included here. For
  # this case we need to make sure that we don't cause duplicate detections on multiple dirs.
  #
  if( eregmatch( pattern:"<title>[^<]*Round[Cc]ube Webmail[^<]*</title>", string:buf, icase:FALSE ) ||
      ( "rcmloginuser" >< buf && "rcmloginpwd" >< buf ) || "new rcube_webmail();" >< buf ) {

    version = "unknown";
    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    # nb:
    # - Since version 1.5.0 the project has switched from a CHANGELOG to CHANGELOG.md as seen here:
    #   - https://github.com/roundcube/roundcubemail/blob/1.4.13/CHANGELOG
    #   - https://raw.githubusercontent.com/roundcube/roundcubemail/1.5.0/CHANGELOG.md
    # - As an update might have left the older CHANGELOG behind (happens when using their upgrade
    #   script) we're trying the .md first and falling back to the older afterwards
    # - The "RELEASE 1.2.3" string below seems to be available since around version 0.4.1:
    #   https://github.com/roundcube/roundcubemail/blob/v0.4.2/CHANGELOG
    #   which should be enough for our purpose
    # - Both currently below tested "initial" response checks have been checked starting from
    #   version 0.4.1 up to the current 1.6.1

    foreach url( make_list( dir + "/CHANGELOG.md", dir + "/CHANGELOG" ) ) {

      buf2 = http_get_cache( item:url, port:port );
      if( ! buf2 || buf2 !~ "^HTTP/1\.[01] 200" ||
          ( "# Changelog Roundcube Webmail" >!< buf2 && "CHANGELOG Roundcube Webmail" >!< buf2 )
        )
        continue;

      # ## Release 1.6.6
      # ## Release 1.6.1
      # ## Release 1.5.10
      # RELEASE 1.4.13
      # RELEASE 1.4.10
      # RELEASE 0.4.1
      # RELEASE 0.5-RC
      vers = eregmatch( pattern:"(RELEASE|## Release) (([0-9.]+)(-([a-zA-Z]+))?)", string:buf2, icase:FALSE );
      if( ! isnull( vers[2] ) ) {
        version = vers[2];
        conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        break;
      }
    }

    cpe = "cpe:/a:roundcube:webmail";

    if( version != "unknown" ) {
      # nb: Example array indices:
      # [ 0: 'RELEASE 0.5-RC', 1: 'RELEASE', 2: '0.5-RC', 3: '0.5', 4: '-RC', 5: 'RC' ]
      # [ 0: '## Release 1.5.3', 1: '## Release', 2: '1.5.3', 3: '1.5.3' ]
      if( ! isnull( vers[4] ) )
        cpe += ":" + vers[3] + ":" + tolower( vers[5] );
      else
        cpe += ":" + version;
    }

    # nb: Newer versions (around 1.4.x) seems to provide this in the HTML source code:
    #
    # "rcversion":10611, -> Version 1.6.11
    # "rcversion":10610, -> Version 1.6.10
    # "rcversion":10603, -> Version 1.6.3
    # "rcversion":10600, -> Version 1.6.0
    # "rcversion":10502, -> Version 1.5.2
    # "rcversion":10500, -> Version 1.5.0
    # "rcversion":10413, -> Version 1.4.13
    # "rcversion":10409, -> Version 1.4.9
    # "rcversion":10401, -> Version 1.4.1
    #
    # For these we need some special handling here...
    if( version == "unknown" && '"rcversion"' >< buf ) {
      vers = eregmatch( string:buf, pattern:'"rcversion"\\s*:\\s*([0-9]{5}),', icase:FALSE );
      if( vers[1] ) {
        tmp_vers = vers[1];

        # nb: Those two need to be "reset" so that we don't append additional data to them if they
        # had been defined in a previous loop / iteration.
        minor_vers = NULL;
        patch_vers = NULL;

        # nb: No need for "special" handling / checks below (e.g. checking if an array index is
        # there) as we have always five numbers due to our strict regex above.
        major_vers = tmp_vers[0];

        # Handle cases where the minor version has a leading 0 which can be dropped in this case
        if( tmp_vers[1] != "0" )
          minor_vers = tmp_vers[1];
        minor_vers += tmp_vers[2];

        # Same as above
        if( tmp_vers[3] != "0" )
          patch_vers = tmp_vers[3];
        patch_vers += tmp_vers[4];

        # Final "building" of the version
        version = major_vers + "." + minor_vers + "." + patch_vers;
        cpe += ":" + version;
      }
    }

    set_kb_item( name:"roundcube/detected", value:TRUE );
    set_kb_item( name:"roundcube/http/detected", value:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Roundcube Webmail",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:vers[0] ),
                 port:port );
  }
}

exit( 0 );
