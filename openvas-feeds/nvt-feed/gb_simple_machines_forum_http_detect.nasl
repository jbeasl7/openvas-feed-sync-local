# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800557");
  script_version("2025-07-24T05:43:49+0000");
  script_tag(name:"last_modification", value:"2025-07-24 05:43:49 +0000 (Thu, 24 Jul 2025)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Simple Machines Forum (SMF) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.simplemachines.org/");

  script_tag(name:"summary", value:"HTTP based detection of Simple Machines Forum (SMF).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

rootInstalled = FALSE;
versionDebug  = FALSE;

detection_patterns = make_list(

  # <span class="smalltext" style="display: inline; visibility: visible; font-family: Verdana, Arial, sans-serif;"><a href="http://www.simplemachines.org/" title="Simple Machines Forum" target="_blank">Powered by SMF 1.1.19</a> |
  # <a href="http://www.simplemachines.org/about/copyright.php" title="Free Forum Software" target="_blank">SMF &copy; 2006-2009, Simple Machines</a>
  ">Powered by SMF",

  # Both at the same system:
  # <span class="smalltext" style="display: inline; visibility: visible; font-family: Verdana, Arial, sans-serif;"><a href="http://<redacted>/index.php?action=credits" title="Simple Machines Forum" target="_blank" class="new_win">SMF 2.0.10</a> |
  # <a href="http://www.simplemachines.org/about/smf/license.php" title="License" target="_blank" class="new_win">SMF &copy; 2015</a>, <a href="http://www.simplemachines.org" title="Simple Machines" target="_blank" class="new_win">Simple Machines</a>
  #
  # or:
  #
  # <li class="copyright"><a href="https://<redacted>/index.php?action=credits" title="License" target="_blank" rel="noopener">SMF 2.1.6 &copy; 2025</a>, <a href="https://www.simplemachines.org" title="Simple Machines" target="_blank" rel="noopener">Simple Machines</a></li>
  #
  # <li class="copyright"><a href="https://<redacted>/index.php?action=credits" title="License" target="_blank" rel="noopener">SMF 2.1 RC2 &copy; 2019</a>, <a href="http://www.simplemachines.org" title="Simple Machines" target="_blank" rel="noopener">Simple Machines</a></li>
  '">Simple Machines</a>',
  'title="Simple Machines"',

  # var smf_theme_url = "https://<redacted>/Themes/default";
  #
  # nb: Old 1.x versions only had these:
  # var smf_theme_url = "https://<redacted>/Themes/custom1";
  # var smf_images_url = "https://<redacted>/Themes/custom1/images";
  # var smf_scripturl = "https://<redacted>/index.php";
  # var smf_iso_case_folding = false;
  # var smf_charset = "ISO-8859-1";
  #
  # while newer also have e.g.:
  #
  # var smf_session_id = "<redacted>";
  #
  'var smf_theme_url = "[^"]+";'
);

foreach dir( make_list_unique( "/", "/community", "/smf", "/smf1", "/smf2", "/forum", "/board", "/sm_forum", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled )
    break;

  found = FALSE;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( res && res =~ "^HTTP/1\.[01] 200" ) {

    foreach detection_pattern( detection_patterns ) {

      # nb: Using eregmatch() here to not report "too much" in the concluded reporting later.
      concl = eregmatch( string:res, pattern:detection_pattern, icase:FALSE );
      if( concl[0] ) {

        if( concluded )
          concluded += '\n';
        concluded += "  " + concl[0];
        found = TRUE;
      }
    }
  }

  if( ! found ) {

    url = dir + "/";
    res = http_get_cache( item:url, port:port );
    if( res && res =~ "^HTTP/1\.[01] 200" ) {

      foreach detection_pattern( detection_patterns ) {

        # nb: Using eregmatch() here to not report "too much" in the concluded reporting later.
        concl = eregmatch( string:res, pattern:detection_pattern, icase:FALSE );
        if( concl[0] ) {

          if( concluded )
            concluded += '\n';
          concluded += "  " + concl[0];
          found = TRUE;
        }
      }
    }
  }

  if( found ) {

    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    final_ver = "unknown";
    if( dir == "" )
      rootInstalled = TRUE;

    # rel="noopener">SMF 2.1.6 &copy; 2025</a>
    # rel="noopener">SMF 2.1.4 &copy; 2023</a>
    # rel="noopener">SMF 2.1 RC2 &copy; 2019</a>
    # class="new_win">SMF 2.0.10</a> |
    # class="new_win">SMF 2.0.19</a> |
    # class="new_win">SMF 2.0.1</a> |
    vers = eregmatch( pattern:">SMF ([0-9.]+)(\.| )?(RC[0-9])?[^<]*</a>", string:res );
    if( ! isnull( vers[1] ) ) {

      concluded += '\n  ' + vers[0];

      if( isnull( vers[3] ) )
        final_ver = vers[1];
      else
        final_ver = vers[1] + " " + vers[3];
    }

    if( final_ver == "unknown" ) {

      # target="_blank">Powered by SMF 1.1.19</a>
      # target="_blank">Powered by SMF 1.1.21</a>
      vers = eregmatch( pattern:">Powered by SMF ([0-9.]+)(\.| )?(RC[0-9])?[^<]*</a>", string:res );
      if( ! isnull( vers[1] ) ) {

        concluded += '\n  ' + vers[0];

        if( isnull( vers[3] ) )
          final_ver = vers[1];
        else
          final_ver = vers[1] + " " + vers[3];
      }
    }

    if( final_ver == "unknown" ) {

      highest_ver = "unknown";

      # If version is hidden try some common backup file names to
      # find the highest available version exposed.
      foreach file( make_list( "/index.php~", "/proxy.php~", "/Sources/Admin.php", "/Sources/Class-CurlFetchWeb.php~",
                               "/Sources/LogInOut.php~", "/Sources/ManageServer.php~", "/Sources/Post.php~",
                               "/Sources/Profile-Modify.php~", "/Sources/Profile-View.php~", "/Sources/SendTopic.php~",
                               "/Sources/Subs.php~", "/Sources/Subs-Db-mysql.php~", "/Sources/Who.php~",
                               "/Themes/core/Login.template.php~", "/Themes/core/index.template.php~",
                               "/Themes/default/Login.template.php~", "/Themes/default/index.template.php~" ) ) {
        url = dir + file;
        res = http_get_cache( item:url, port:port );

        # * @version 2.1.6
        # * @version 2.0.19
        vers = eregmatch( pattern:"\* @version ([0-9.]+)(\.| )?(RC[0-9])?", string:res );
        if( ! isnull( vers[1] ) ) {

          if( highest_ver == "unknown" ) {

            tmp_concluded = vers[0];
            tmp_conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

            if( isnull( vers[3] ) )
              highest_ver = vers[1];
            else
              highest_ver = vers[1] + " " + vers[3];
          }

          if( isnull( vers[3] ) )
            tmp_ver = vers[1];
          else
            tmp_ver = vers[1] + " " + vers[3];

          if( versionDebug ) display( "Current detected version on " + url + ": " + tmp_ver + ", previous version: " + highest_ver );

          if( version_is_greater( version:tmp_ver, test_version:highest_ver ) ) {
            highest_ver = tmp_ver;
            tmp_concluded = vers[0];
            tmp_conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
          }
        }
      }

      if( highest_ver != "unknown" ) {
        final_ver = highest_ver;
        concluded += '\n  ' + tmp_concluded;
        conclUrl += '\n  ' + tmp_conclUrl;
      }
    }

    set_kb_item( name:"www/can_host_tapatalk", value:TRUE ); # nb: Used in sw_tapatalk_detect.nasl for plugin scheduling optimization
    set_kb_item( name:"smf/detected",value:TRUE );
    set_kb_item( name:"smf/http/detected",value:TRUE );

    cpe = build_cpe( value:tolower( final_ver ), exp:"^([0-9.]+) ?(RC[0-9])?", base:"cpe:/a:simplemachines:smf:" );
    if( ! cpe )
      cpe = "cpe:/a:simplemachines:smf";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Simple Machines Forum (SMF)",
                                              version:final_ver,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:concluded ),
                 port:port );
  }
}

exit( 0 );
