# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111023");
  script_version("2025-05-14T05:40:11+0000");
  script_tag(name:"last_modification", value:"2025-05-14 05:40:11 +0000 (Wed, 14 May 2025)");
  script_tag(name:"creation_date", value:"2015-07-20 13:14:40 +0200 (Mon, 20 Jul 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("MyBB Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of MyBB.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_add_preference(name:"MyBB Admin User", value:"", type:"entry", id:1);
  script_add_preference(name:"MyBB Admin Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://mybb.com/");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/forum", "/forums", "/mybb", "/MyBB", "/board", "/boards", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );

  if( ( concl = eregmatch( string:res, pattern:'(>MyBB|>MyBB Group<|var MyBBEditor|onclick="MyBB.quickLogin\\(\\))', icase:FALSE ) ) &&
      "mybb[lastvisit]" >< res ) {
    concluded = "  " + chomp( concl[0] );
    concludedurl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    version = "unknown";
    extra = NULL;
    vers = eregmatch( pattern:">MyBB ([0-9.]+).?<", string:res );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      concluded += '\n  ' + vers[0];
    } else {
      vers = eregmatch( pattern:"general\.js\?ver=([0-9]+)", string:res );
      if( ! isnull( vers[1] ) ) {
        ver = vers[1];
        # we get e.g. 1803 for 1.8.3 so strip the 0
        if( strlen( ver ) > 3 && ver[2] == 0 )
          i = 3;
        else
          i = 2;
        version = ver[0] + '.' + ver[1] + '.' + substr( ver, i );

        if( version != "1.8.27" && version != "1.8.21" )
          concluded += '\n  ' + vers[0];
      }
    }
    # nb: Starting with version 1.8.21, it seems the previous pattern was not used anymore
    # therefore unauthenticated version extraction is no longer reliable
    if( version == "unknown" || version == "1.8.27" || version == "1.8.21" ) {
      version = "unknown";
      user = script_get_preference( "MyBB Admin User", id:1 );
      pass = script_get_preference( "MyBB Admin Password", id:2 );
      if( ! user && ! pass ) {
        extra = "Note: No admin user and password credentials for web authentication were provided. Please provide these for version extraction.";
      } else if( ! user && pass ) {
        extra = "Note: Password for web authentication was provided but Admin User is missing.";
      } else if( user && ! pass ) {
        extra = "Note: Admin User for web authentication was provided but Password is missing.";
      } else if( user && pass ) {
        # nb: First we make sure the admin login page actually exists
        url = "/admin/index.php";
        req = http_get_req( port:port, url:url );
        res = http_keepalive_send_recv( port:port, data:req );
        # nb: To make sure we do not miss the admin login page if also installed in the same location
        if( ! res || res !~ "^HTTP/(1\.[01]|2) (2[02]0|303)" ) {
          url = dir + "/admin/index.php";
          req = http_get_req( port:port, url:url );
          res = http_keepalive_send_recv( port:port, data:req );
        }
        if( res && res =~ "^HTTP/(1\.[01]|2) (2[02]0|303)" ) {
          post_data = "username=" + user + "&password=" + pass + "&do=login";

          headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );
          req = http_post_put_req( port:port, url:url, data:post_data, add_headers:headers );
          res = http_keepalive_send_recv( port:port, data:req );

          if( res && res =~ "^HTTP/(1\.[01]|2) (2[02]0|303)" && "MyBB Admin-CP" >< res ) {
            # MyBB Version</strong></td>
            # <td class="alt_col" width="25%">1.8.38</td>
            vers = eregmatch( string:res, pattern:"MyBB Version</strong></td>\s*<td[^>]+>([0-9.]+)", icase:FALSE );
            if( vers[1] ) {
              version = vers[1];
              concluded += '\n  ' + vers[0];
              concludedurl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
            }
          } else { # nb: POST admin/index.php did not work
            extra = "Note: Admin username and password were provided but authentication failed.";
          }
        } else { # nb: GET admin/index.php did not work
          extra = "Note: Admin username and password were provided but authentication failed.";
        }

      }
    }

    set_kb_item( name:"mybb/detected", value:TRUE );
    set_kb_item( name:"mybb/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:mybb:mybb:" );
    if( ! cpe )
      cpe = "cpe:/a:mybb:mybb";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"MyBB",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              extra:extra,
                                              concluded:concluded,
                                              concludedUrl:concludedurl ),
                                              port:port );

    exit( 0 );
  }
}

exit( 0 );
