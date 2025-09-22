# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105951");
  script_version("2025-07-16T05:43:53+0000");
  script_tag(name:"last_modification", value:"2025-07-16 05:43:53 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"creation_date", value:"2015-02-06 14:11:41 +0700 (Fri, 06 Feb 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Gogs (Go Git Service) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 3000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Gogs (Go Git Service).");

  script_add_preference(name:"Gogs Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Gogs Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://gogs.io/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port( default:3000 );

detection_patterns = make_list(
  # <title>Sign In - Gogs</title>
  # nb: Title tag can be changed by the admin so additional pattern are used.
  "^\s*<title>Sign In - Gogs[^<]*</title>",
  # Set-Cookie: i_like_gogs=cb882774ea538f46; Path=/; HttpOnly
  # Set-Cookie: i_like_gogits=3c1e042a611f849c; Path=/; HttpOnly
  # set-cookie: i_like_gogits=f21cdf87390436d8; Path=/; HttpOnly
  "^[Ss]et-[Cc]ookie\s*:\s*i_like_gog(it)?s=.+",
  # <meta name="author" content="Gogs" />
  # <meta name="description" content="Gogs is a painless self-hosted Git service" />
  # <meta name="keywords" content="go, git, self-hosted, gogs">
  '"description" content="Gogs is a painless self-hosted Git service"' );

foreach dir( make_list_unique( "/", "/gogs", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/user/login";
  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  found = 0;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach pattern( detection_patterns ) {

    concl = egrep( string:res, pattern:pattern, icase:FALSE );
    if( concl ) {
      if( concluded )
        concluded += '\n';

      # nb: Minor formatting change for the reporting.
      concl = chomp( concl );
      concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
      concluded += "  " + concl;

      found++;
    }
  }

  if( found > 0 ) {

    version = "unknown";
    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    goconclUrl = conclUrl;

    ver = eregmatch( string:res, pattern:"GoGits.*Version: ([0-9.]+)" );
    if ( ! isnull( ver[1] ) ) {
      version = ver[1];
      concluded += '\n  ' + ver[0];
    } else {
      # 2018 Gogs Version: 0.11.86.0130 Page: <strong>0ms</strong> Template: <strong>0ms</strong>
      # 2017 Gogs Version: 0.9.141.0211 Page: <strong>0ms</strong> Template: <strong>0ms</strong>
      ver = eregmatch( string:res, pattern:"Gogs Version: ([0-9.]+)" );
      if( ! isnull( ver[1] ) ) {
        version = ver[1];
        concluded += '\n  ' + ver[0];
      } else {
        user = script_get_preference( "Gogs Web UI Username", id:1 );
        pass = script_get_preference( "Gogs Web UI Password", id:2 );

        if( ! user && ! pass ) {
          extra += "  Note: No username and password for web authentication were provided. These could be provided for extended version extraction.";
        } else if( ! user && pass ) {
          extra += "  Note: Password for web authentication was provided but username is missing. Please provide both.";
        } else if( user && ! pass ) {
          extra += "  Note: Username for web authentication was provided but password is missing. Please provide both.";
        } else if( user && pass ) {
          url = dir + "/";

          req = http_get( port:port, item:url );
          res = http_keepalive_send_recv( port:port, data:req );

          csrf = eregmatch( pattern:'name="_csrf"\\s+content="([^"]+)"', string:res );
          if( ! isnull( csrf[1] ) ) {
            url = dir + "/user/login";

            headers = make_array( "Content-Type", "application/x-www-form-urlencoded");

            data = "_csrf=" + csrf[1] + "&user_name=" + user + "&password=" + pass;

            req = http_post_put_req( port:port, url:url, data:data, add_headers:headers );
            res = http_keepalive_send_recv( port:port, data:req );

            if( res =~ "^HTTP/1\.[01] 302" ) {
              cookie = http_get_cookie_from_header( buf:res, pattern:"(i_like_gogs=[^; ]+)" );
              if( cookie ) {
                vers_url = dir + "/admin";

                headers = make_array( "Cookie", cookie );

                req = http_get_req( port:port, url:vers_url, add_headers:headers );
                vers_res = http_keepalive_send_recv( port:port, data:req );

                # <dt>Application version</dt>
                # <dd>0.14.0&#43;dev</dd>
                vers = eregmatch( pattern:"Application version</dt>[^>]+>([0-9.]+)[^<]*", string:vers_res );
                if( ! isnull( vers[1] ) ) {
                  version = vers[1];
                  conclUrl += '\n  ' + http_report_vuln_url( port:port, url:vers_url, url_only:TRUE );
                  concluded += '\n  ' + vers[0];
                }
              }
            } else {
              extra += "  Note: Username and password were provided but authentication failed.";
            }
          } else {
            extra += "  Note: Username and password were provided but authentication failed.";
          }
        }
      }
    }

    set_kb_item( name:"gogs/detected", value:TRUE );
    set_kb_item( name:"gogs/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base: "cpe:/a:gogs:gogs:" );
    if( ! cpe )
      cpe = "cpe:/a:gogs:gogs";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Gogs (Go Git Service)",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:concluded, extra:extra ),
                 port:port );

    goVersion = "unknown";

    # <span class="version">Go1.10.2</span>
    # <span class="version">Go1.7.5</span>
    goVer = eregmatch( string:res, pattern:'version">Go([0-9.]+)' );
    if( ! isnull( goVer[1] ) ) {
      goVersion = goVer[1];
    } else if( vers_res ) {
      # <dt>Go version</dt>
      # <dd>go1.24.4</dd>
      goVer = eregmatch( pattern:"Go version</dt>[^>]+>go([0-9.]+)", string:vers_res );
      if( ! isnull( goVer[1] ) ) {
        goVersion = goVer[1];
        goconclUrl += '\n  ' + http_report_vuln_url( port:port, url:vers_url, url_only:TRUE );
      }
    }

    cpe = build_cpe( value:goVersion, exp:"^([0-9.]+)", base: "cpe:/a:golang:go:" );
    if( ! cpe )
      cpe = "cpe:/a:golang:go";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Go Programming Language",
                                              version:goVersion,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:goconclUrl,
                                              concluded:goVer[0] ),
                 port:port );
  }
}

exit( 0 );
