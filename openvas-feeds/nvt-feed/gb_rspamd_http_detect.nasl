# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114368");
  script_version("2024-02-20T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-20 11:12:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Rspamd Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://rspamd.com");

  script_tag(name:"summary", value:"HTTP based detection of Rspamd.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:443 );

detection_patterns = make_list(
  # Server: rspamd/1.8.1
  # Server: rspamd/1.9.4
  # Server: rspamd/3.7.3
  "^[Ss]erver\s*:\s*rspamd",
  # <title>Rspamd Web Interface</title>
  "<title>Rspamd Web Interface</title>",
  # <link href="./css/rspamd.css" rel="stylesheet">
  '<link href="[^"]*/css/rspamd\\.css" rel="stylesheet">',
  # <a class="navbar-brand" href="."><img src="./img/rspamd_logo_navbar.png" style="width: 67px; margin-top: -16px;"/></a>
  # <img class="img-fluid w-auto mh-100 mx-auto" src="./img/rspamd_logo_navbar.png" alt="Rspamd" />
  # <img src="./img/rspamd_logo_navbar.png" alt="Rspamd">
  'src="[^"]*/img/rspamd_logo_navbar\\.png"',
  # <h3>Login to Rspamd</h3>
  # <h6 class="modal-title fw-bolder">Login to Rspamd</h6>
  "<h[0-9][^>]*>Login to Rspamd</h[0-9]>",
  # <span class="h6 fw-bolder my-2">Learn Rspamd</span>
  # <h5>Learn RSPAMD</h5>
  "<[^>]+>Learn [Rr][Ss][Pp][Aa][Mm][Dd]</[^>]+>"
);

found = 0;
concluded = ""; # nb: To make openvas-nasl-lint happy...

# nb: If a proxy is placed in front the service could be available at an arbitrary location...
foreach dir( make_list_unique( "/", "/rspamd", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";
  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "^HTTP/1\.[01] [0-9]+" )
    continue;

  foreach pattern( detection_patterns ) {

    concl = egrep( string:res, pattern:pattern, icase:FALSE );
    if( concl ) {

      # Existence of the banner is always counting as a successful detection.
      if( "erver" >< pattern && "rspamd" >< pattern )
        found += 2;
      else
        found++;

      # nb: Minor formatting change for the reporting.
      concl_split = split( concl, keep:FALSE );
      foreach _concl( concl_split ) {

        # nb: This could exist multiple times, only add them once to the reporting
        if( pattern =~ "rspamd_logo_navbar" && concluded =~ "rspamd_logo_navbar" )
          continue;

        if( concluded )
          concluded += '\n';

        _concl = chomp( _concl );
        _concl = ereg_replace( string:_concl, pattern:"^(\s+)", replace:"" );
        concluded += "  " + _concl;
      }
    }
  }

  # nb: No need to continue with the additional URLs...
  if( found > 1 )
    break;
}

if( found > 1 ) {

  version = "unknown";
  conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  set_kb_item( name:"rspamd/detected", value:TRUE );
  set_kb_item( name:"rspamd/http/detected", value:TRUE );

  # nb:
  # - This is not always there...
  # - See above for a few examples
  vers = eregmatch( pattern:"[Ss]erver\s*:\s*rspamd/([0-9.]+)", string:res );
  if( vers[1] )
    version = vers[1];

  cpe = build_cpe( value:version, exp:"^([0-9.-]+)", base:"cpe:/a:rspamd_project:rspamd:" );
  if( ! cpe )
    cpe = "cpe:/a:rspamd_project:rspamd";

  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", runs_key:"unixoide", desc:"Rspamd Detection (HTTP)" );

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Rspamd",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded,
                                            concludedUrl:conclUrl ),
               port:port );
}

exit( 0 );
