# SPDX-FileCopyrightText: 2009 Angelo Compagnucci
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100330");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-10-30 14:42:19 +0100 (Fri, 30 Oct 2009)");
  script_name("Joomla Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Angelo Compagnucci");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Joomla.");

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

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/cms", "/joomla", http_cgi_dirs( port:port ) ) ) {

  installed = FALSE;
  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( ! buf || "topic does not exist" >< buf || 'content="DokuWiki"' >< buf )
    continue;

  if( egrep( pattern:'.*content="joomla.*', string:buf ) ||
      egrep( pattern:'.*content="Joomla.*', string:buf ) ||
      egrep( pattern:'.*href="/administrator/templates.*', string:buf ) ||
      egrep( pattern:'.*src="/media/system/js.*', string:buf ) ||
      egrep( pattern:'.*src="/templates/system.*', string:buf ) ) {
    installed = TRUE;
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  } else {

    url = dir + "/.htaccess";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( egrep( pattern:".*# @package Joomla.*", string:buf ) ) {
      installed = TRUE;
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    } else {
      url = dir + "/templates/system/css/editor.css";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( egrep( pattern:".*JOOMLA.*", string: buf ) ) {
        installed = TRUE;
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      } else {
        url = dir + "/includes/js/mambojavascript.js";
        req = http_get( item:url, port:port );
        buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

        if( egrep( pattern:".*@package Joomla.*", string:buf ) ) {
          installed = TRUE;
          conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }
  }

  if( installed ) {

    version = "unknown";

    url = dir + "/administrator/";

    buf = http_get_cache( item:url, port:port );
    if( buf =~ "^HTTP/1\.[01] 200" )
      language = eregmatch( string:buf, pattern:'lang="(..-..)"' );

    # Always use en-GB as a default and fallback to the detected language later
    default_lang = make_list( "en-GB" );

    if( ! isnull( language[1] ) ) {
      lang = substr( language[1], 0, 1 ) + "-" + toupper( substr( language[1], 3 ) );
      langs = make_list( default_lang, lang );
    } else {
      langs = default_lang;
    }

    check_files = make_list( "install.xml",   # For 4.x and later
                             lang + ".xml" ); # For 3.x and below

    foreach check_file( check_files ) {
      foreach lang( langs ) {
        url = dir + "/administrator/language/" + lang + "/" + check_file;
        req = http_get( item:url, port:port );
        buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

        if( buf =~ "^HTTP/1\.[01] 200" )
          ver = eregmatch( string:buf, pattern:"<version>([^<]+)</version>" );

        if( ! isnull( ver[1] ) ) {
          if( conclUrl )
            conclUrl += " and " + http_report_vuln_url( url:url, port:port, url_only:TRUE );
          version = ver[1];
          concluded = ver[0];
          break;
        }
      }
      if( version != "unknown" )
        break;
    }

    if( version == "unknown" ) {

      url = dir + "/";
      buf = http_get_cache( item:url, port:port );

      if( buf =~ "^HTTP/1\.[01] 200" )
        language = eregmatch( string:buf, pattern:'lang="(..-..)"' );

      if( ! isnull( language[1] ) ) {
        lang = substr( language[1], 0, 1 ) + "-" + toupper( substr( language[1], 3 ) );
        langs = make_list( default_lang, lang );
      } else {
        langs = default_lang;
      }

      check_files = make_list( "install.xml",   # For 4.x and later
                               lang + ".xml" ); # For 3.x and below

      foreach check_file( check_files ) {
        foreach lang( langs ) {

          url = dir + "/language/" + lang + "/" + check_file;
          req = http_get( item:url, port:port );
          buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

          if( buf =~ "^HTTP/1\.[01] 200" )
            ver = eregmatch( string:buf, pattern:"<version>([^<]+)</version>" );

          if( ! isnull( ver[1] ) ) {
            if( conclUrl )
              conclUrl += " and " + http_report_vuln_url( url:url, port:port, url_only:TRUE );
            version = ver[1];
            concluded = ver[0];
            break;
          }
        }
        if( version != "unknown" )
          break;
      }
    }

    if( version == "unknown" ) {

      url = dir + "/components/com_user/user.xml";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( buf =~ "^HTTP/1\.[01] 200" )
        ver = eregmatch( string:buf, pattern:"<version>([^<]+)</version>" );

      if( ! isnull( ver[1] ) ) {
        if( conclUrl )
          conclUrl += " and " + http_report_vuln_url( url:url, port:port, url_only:TRUE );
        version = ver[1];
        concluded = ver[0];
      }
    }

    if( version == "unknown" ) {

      # This file version is not really reliable. On e.g. Joomla 4.0.3 this version is:
      # <version>3.0.0</version>
      url = dir + "/modules/mod_login/mod_login.xml";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( buf =~ "^HTTP/1\.[01] 200" ) {
        # <version>3.0.0</version>
        ver = eregmatch( string:buf, pattern:"<version>([^<]+)</version>" );
      }

      if( ! isnull( ver[1] ) ) {
        if( conclUrl )
          conclUrl += " and " + http_report_vuln_url( url:url, port:port, url_only:TRUE );
        version = ver[1];
        concluded = ver[0];
      }
    }

    set_kb_item( name:"joomla/installed", value:TRUE );
    set_kb_item( name:"joomla/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:joomla:joomla:" );
    if( ! cpe )
      cpe = "cpe:/a:joomla:joomla";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Joomla",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:concluded ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
