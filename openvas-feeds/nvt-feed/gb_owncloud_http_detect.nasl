# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103564");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2012-09-12 14:18:24 +0200 (Wed, 12 Sep 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ownCloud / ownCloud Infinite Scale Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Product detection");
  # nb: Nextcloud needs to be detected before, that's why the dependency is included here
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "gb_nextcloud_server_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ownCloud / ownCloud Infinite Scale
  (oCIS).");

  script_xref(name:"URL", value:"https://owncloud.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", "/oc", "/owncloud", "/ownCloud", "/OwnCloud", "/cloud", http_cgi_dirs( port:port ) ) ) {

  # nb: From gb_nextcloud_server_http_detect.nasl to avoid double detection of Nextcloud and ownCloud
  if( get_kb_item( "nextcloud/server/install/" + host + "/" + port + "/" + dir ) )
    continue;

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/status.php";
  buf = http_get_cache( item:url, port:port );

  # nb: Try again with the IP which might be included in the trusted_domain setting.
  # This could could allow us to gather the version.
  if( "You are accessing the server from an untrusted domain" >< buf ) {
    req = http_get_req( port:port, url:url, host_header_use_ip:TRUE );
    buf = http_keepalive_send_recv( port:port, data:req );
  }

  # nb: Don't check for 200 as a 400 will be returned when accessing via an untrusted domain
  #
  # Example responses:
  #
  # {"installed":"true","maintenance":"false","needsDbUpgrade":"false","version":"10.0.2.1","versionstring":"10.0.2","edition":"Community","productname":"ownCloud"}
  # {"installed":"true","maintenance":"false","needsDbUpgrade":"false","version":"10.0.2.9","versionstring":"10.0.2 RC1","edition":"Community","productname":"ownCloud"}
  # {"installed":true,"maintenance":false,"needsDbUpgrade":false,"version":"10.14.0.3","versionstring":"10.14.0","edition":"Community","productname":"ownCloud","product":"ownCloud"}
  #
  # On ownCloud Infinite Scale the strings are spread accorss multiple lines:
  #
  #{
  #    "installed": true,
  #    "maintenance": false,
  #    "needsDbUpgrade": false,
  #    "version": "10.11.0.0",
  #    "versionstring": "10.11.0",
  #    "edition": "Community",
  #    "productname": "Infinite Scale",
  #    "product": "Infinite Scale",
  #    "productversion": "5.0.5"
  #}
  #
  # nb: EGroupware is using a similar status.php like e.g. the following and thus has been excluded here:
  #
  # {"installed":"true","version":"4.80.1","versionstring":"EGroupware 23.1.005","edition":""}
  # {"installed":"true","version":"4.80.1","versionstring":"EGroupware 21.1.001","edition":""}
  # {"installed":"true","version":"4.80.1","versionstring":"EGroupware 17.1.007","edition":""}
  # {"installed":"true","version":"4.80.1","versionstring":"EGroupware 17.1","edition":""}
  # {"installed":"true","version":"4.80.1","versionstring":"EGroupware 1.8.007","edition":""}
  #
  if( "egroupware" >!< tolower( buf ) &&
      buf !~ '"product(name)?"\\s*:\\s*"[^"]*Nextcloud[^"]*"' && # nb: Don't detect ownCloud / oCIS as Nextcloud
    ( eregmatch( string:buf, pattern:'"installed"\\s*:\\s*("true"|true)\\s*,\\s*("maintenance"\\s*:\\s*("true"|true|"false"|false)\\s*,\\s*)?("needsDbUpgrade"\\s*:\\s*("true"|true|"false"|false)\\s*,\\s*)?"version"\\s*:\\s*"([0-9.a]+)"\\s*,\\s*"versionstring"\\s*:\\s*"([0-9. a-zA-Z]+)"\\s*,\\s*"edition"\\s*:\\s*"[^"]*"', icase:FALSE ) ||
      ( "You are accessing the server from an untrusted domain" >< buf && ">ownCloud<" >< buf ) ||
      buf =~ '"product(name)?"\\s*:\\s*"[^"]*(ownCloud|Infinite Scale)[^"]*"' || buf =~ 'class="hidden-visually">[^o]*ownCloud' ) ) { # nb: Last fallback if the syntax of the status has changed

    version = "unknown";
    extra = NULL;
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    # nb: Basic auth check for default_http_auth_credentials.nasl
    foreach authurl( make_list( dir + "/remote.php/dav", dir + "/remote.php/webdav" ) ) {

      req = http_get( item:authurl, port:port );
      buf2 = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( buf2 =~ "^HTTP/1\.[01] 401" ) {
        set_kb_item( name:"www/content/auth_required", value:TRUE );
        set_kb_item( name:"www/" + host + "/" + port + "/content/auth_required", value:authurl );
        break;
      }
    }

    if( "You are accessing the server from an untrusted domain" >< buf ) {
      extra = "ownCloud is blocking full access to this server because the scanner is accessing the server via an untrusted domain.";
      extra += " To fix this configure the scanner to access the server on the expected domain.";
    }

    if( buf =~ "Infinite Scale" ) {

      set_kb_item( name:"owncloud_infinite_scale/detected", value:TRUE );
      set_kb_item( name:"owncloud_infinite_scale/http/detected", value:TRUE );

      base_cpe = "cpe:/a:owncloud:owncloud_infinite_scale";
      app_name = "ownCloud Infinite Scale (oCIS)";

      # nb: For some reason oCIS is providing some kind of ownCloud 10 version so we need a
      # different pattern here
      vers = eregmatch( string:buf, pattern:'"productversion"\\s*:\\s*"([0-9.]+)[^"]*"', icase:FALSE );
      if( ! isnull( vers[1] ) )
        version = vers[1];

    } else {

      set_kb_item( name:"owncloud/detected", value:TRUE );
      set_kb_item( name:"owncloud/http/detected", value:TRUE );

      # nb: This is only used for a single "unprotected data dir" VT and also only valid for
      # non-oCIS systems so it is used in this block here.
      set_kb_item( name:"nextcloud_server_or_owncloud/detected", value:TRUE );
      set_kb_item( name:"nextcloud_server_or_owncloud/http/detected", value:TRUE );

      base_cpe = "cpe:/a:owncloud:owncloud";
      app_name = "ownCloud";

      vers = eregmatch( string:buf, pattern:'version"\\s*:\\s*"([0-9.a]+)[^"]*"\\s*,\\s*"versionstring"\\s*:\\s*"([0-9. a-zA-Z]+)[^"]*"', icase:TRUE );
      if( ! isnull( vers[2] ) )
        version = ereg_replace( pattern:" ", replace:"", string:vers[2] );
    }

    cpe = build_cpe( value:version, exp:"^([0-9.a]+)", base:base_cpe + ":" );
    if( ! cpe )
      cpe = base_cpe;

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:app_name,
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              extra:extra,
                                              concludedUrl:conclUrl,
                                              concluded:vers[0] ),
                 port:port );
  }
}

exit( 0 );
