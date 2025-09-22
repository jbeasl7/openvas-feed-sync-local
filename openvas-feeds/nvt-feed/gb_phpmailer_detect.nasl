# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809841");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-12-27 15:57:31 +0530 (Tue, 27 Dec 2016)");
  script_name("PHPMailer Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of PHPMailer Library.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/PHPMailer-master", "/PHPMailer", "/phpmailer", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  mailer   = FALSE;
  conclUrl = NULL;

  foreach path( make_list( "", "/lib" ) ) {

    url = dir + path + "/composer.json";
    res = http_get_cache( item:url, port:port );

    if( res =~ "^HTTP/1\.[01] 200" && '"name": "phpmailer/phpmailer"' >< res && 'class.phpmailer.php' >< res ) {

      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      mailer = TRUE;

      foreach file( make_list( "/VERSION", "/version" ) ) {

        url = dir + path + file;
        res = http_get_cache( item:url, port:port );

        if( res =~ "^HTTP/1\.[01] 200" ) {
          vers = eregmatch( pattern:'\n([0-9.]+)', string:res );
          if( vers[1] ) {
            conclUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
            version = vers[1];
            break;
          }
        }
      }
    }

    if( version ) {
      break;
    } else {
      continue;
    }
  }

  if( ! version ) {

    foreach file( make_list( "/README", "/README.md" ) ) {

      url = dir + file;
      res = http_get_cache( item:url, port:port );

      if( res =~ "^HTTP/1\.[01] 200" &&
          ( 'class.phpmailer.php' >< res && 'PHPMailer!' >< res ) ||
          ( "PHPMailer" >< res && ( "A full-featured email creation and transfer class for PHP" >< res || "Full Featured Email Transfer Class for PHP" >< res ) ) ) {

        conclUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        mailer = TRUE;

        # nb: Quite agend versions like 1.7.x or 2.2.x had ChangeLog.txt, around 5.1.x had changelog.txt
        # and newer had switched to changelog.md
        foreach file( make_list( "/changelog.txt", "/ChangeLog.txt", "/changelog.md" ) ) {

          url = dir + file;
          res = http_get_cache( item:url, port:port );

          # The typo/regex in the public release text is expected as this typo exists in the changelog.txt
          # and ChangeLog.txt but was fixed in the newer changelog.md
          if( res =~ "^HTTP/1\.[01] 200" && res =~ "Change ?Log" && res =~ "\* Ini?tial public release" ) {

            # ## Version 6.0.5 (March 27th 2018)
            # ## Version 5.2.26 (November 4th 2017)
            # Version 5.0.0 (April 02, 2009)
            # Version 5.1 (October 20, 2009)
            # Version 1.73 (Sun, Jun 10 2005)
            vers = eregmatch( pattern:'Version ([0-9.]+)', string:res );
            if( vers[1] ) {
              conclUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
              version = vers[1];
              break;
            }
          }
        }
      }
      if( version ) {
        break;
      } else {
        continue;
      }
    }
  }

  if( ! version ) {

    url = dir + "/extras";
    res = http_get_cache( item:url, port:port);

    if( res =~ "^HTTP/1\.[01] 200" && res =~ "title>Index of.*extras" && '"EasyPeasyICS.php' >< res ) {

      conclUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      mailer = TRUE;
      url = dir + "/VERSION";
      res = http_get_cache( item:url, port:port );

      if( res =~ "^HTTP/1\.[01] 200" ) {
        vers = eregmatch( pattern:'\n([0-9.]+)', string:res );
        if( vers[1] ) {
          conclUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
          version = vers[1];
        }
      }
    }
  }

  if( mailer ) {

    if( ! version )
      version = "unknown";

    set_kb_item( name:"www/" + port + "/phpmailer", value:version );
    set_kb_item( name:"phpmailer/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:phpmailer_project:phpmailer:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:phpmailer_project:phpmailer";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"PHPMailer",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:vers[0] ),
                                              port:port );
  }
}

exit( 0 );
