# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106035");
  script_version("2025-05-07T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-07 05:40:10 +0000 (Wed, 07 May 2025)");
  script_tag(name:"creation_date", value:"2015-08-03 13:44:55 +0700 (Mon, 03 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Froxlor Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Froxlor.");

  script_add_preference(name:"Froxlor Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Froxlor Web UI Password", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://froxlor.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

detection_patterns = make_list(
  # <title>Froxlor Server Management Panel - Installation</title>
  # <title>Froxlor Server Management Panel</title>
  # <title>Froxlor</title>
  "^\s*<title>Froxlor[^<]*</title>",

  # <p>It seems that Froxlor has not been installed yet.</p>
  ">It seems that Froxlor has not been installed yet\.<",

  # <h2>Welcome to Froxlor</h2>
  ">Welcome to Froxlor<",

  # alt="" />&nbsp;Froxlor&nbsp;-&nbsp;Login</b></td>
  # <legend>Froxlor&nbsp;-&nbsp;Login</legend>
  "Froxlor&nbsp;-&nbsp;Login",

  # <img src="templates/Froxlor/assets/img/logo.png" alt="Froxlor Server Management Panel" />
  # <img src="images/Froxlor/logo.png" alt="Froxlor Server Management Panel" />
  # <img src="templates/Sparkle/assets/img/logo.png" alt="Froxlor Server Management Panel" />
  # <img class="align-self-center my-5" src="templates/Froxlor/assets/img/logo.png" alt="Froxlor Server Management Panel"/>
  'alt="Froxlor Server Management Panel"',

  # A newer version of Froxlor has been installed but not yet set up.<br />Only the administrator can log in and finish the update.
  "A newer version of Froxlor has been installed but not yet set up\.<br */>Only the administrator can log in and finish the update\.",

  # Froxlor &copy; 2009-2013 by <a href="http://www.froxlor.org/" rel="external">the Froxlor Team</a>
  # &copy; 2009-2024 by <a href="http://www.froxlor.org/" rel="external">the Froxlor Team</a>
  # &copy; 2009-2024 by <a href="http://www.froxlor.org/" rel="external">the Froxlor Team</a><br />
  # &copy; 2009-2024 by <a href="http://www.froxlor.org/" target="_blank">the Froxlor Team</a>
  # &copy; 2009-2024 by <a href="https://www.froxlor.org/" rel="external" target="_blank">the froxlor team</a><br>
  ">the [Ff]roxlor [Tt]eam<"
);

foreach dir( make_list_unique( "/froxlor", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( port:port, item:url );

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

  if( found > 1 ) {

    version = "unknown";
    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"froxlor/detected", value:TRUE );
    set_kb_item( name:"froxlor/http/detected", value:TRUE );

    user = script_get_preference( "Froxlor Web UI Username", id:1 );
    pass = script_get_preference( "Froxlor Web UI Password", id:2 );

    if( ! user && ! pass ) {
      extra = "Note: No username and password for web authentication were provided. Please pass these for version extraction.";
    } else if( ! user && pass ) {
      extra = "Note: Password for web authentication was provided but Username is missing.";
    } else if( user && ! pass ) {
      extra = "Note: Username for web authentication was provided but Password is missing.";
    } else if( user && pass ) {
      url = dir + "/";

      headers = make_array( "Content-Type", "application/x-www-form-urlencoded" );

      data = "loginname=" + user + "&password=" + pass + "&dologin=";

      req = http_post_put_req( port:port, url:url, data:data, add_headers:headers );
      res = http_keepalive_send_recv( port:port, data:req );

      if( res =~ "^HTTP/1\.[01] 302" && "admin_index.php" >< res ) {
        cookie = http_get_cookie_from_header( buf:res, pattern:"(PHPSESSID=[^; ]+)" );

        url = dir + "/lib/ajax.php?action=updatecheck";

        headers = make_array( "X-Requested-With", "XMLHttpRequest",
                              "Cookie", cookie );

        req = http_get_req( port:port, url:url, add_headers:headers );
        res = http_keepalive_send_recv( port:port, data:req );

        # Your current version is: 2.2.7
        vers = eregmatch( pattern:"Your current version is\s*:\s*([0-9.]+)", string:res );
        if( ! isnull( vers[1] ) ) {
          version = vers[1];
          conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      } else {
        extra = "Note: Username and Password were provided but authentication failed or user has not enough privileges.";
      }
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:froxlor:froxlor:" );
    if( ! cpe )
      cpe = "cpe:/a:froxlor:froxlor";

    # While written in PHP this seems to be usually only installed on Linux/Unix systems
    os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", port:port, desc:"Froxlor Detection (HTTP)", runs_key:"unixoide" );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Froxlor", version:version, install:install, cpe:cpe,
                                              concluded:concluded, concludedUrl:conclUrl, extra:extra ),
                 port:port );

    # nb: Usually only installed once
    exit( 0 );
  }
}

exit( 0 );
