# SPDX-FileCopyrightText: 2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13858");
  script_version("2025-06-04T05:40:50+0000");
  script_tag(name:"last_modification", value:"2025-06-04 05:40:50 +0000 (Wed, 04 Jun 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("osTicket Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 George A. Theall");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of osTicket.");

  script_xref(name:"URL", value:"http://www.osticket.com/");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

# Git hash to version translation from https://github.com/osTicket/osTicket/releases
lookup_table = make_array("53339df", "1.18.2",
                          "4689926", "1.18.1",
                          "724de45", "1.18",
                          "3ff35ad", "1.17.6",
                          "7c20036", "1.17.5",
                          "ea462cb", "1.17.4",
                          "8bd22d0", "1.17.3",
                          "8fbc7ee", "1.17.2",
                          "58bf538", "1.17.1",
                          "1d8b790", "1.17",
                          "356e156", "1.17-rc4",
                          "34c64f1", "1.17-rc3",
                          "d821546", "1.17-rc2",
                          "9f51d46", "1.17-rc1",
                          "30ef1cc", "1.16.6",
                          "b48bf7e", "1.16.5",
                          "1d11ee6", "1.16.4",
                          "e148727", "1.16.3",
                          "39ab0c5", "1.16.2",
                          "b42ddc7", "1.16.1",
                          "27b8f55", "1.16",
                          "0daca43", "1.15.8",
                          "26ab7e9", "1.15.7",
                          "1a64b84", "1.15.6",
                          "2ba1d8e", "1.15.5",
                          "6bd7884", "1.15.4",
                          "65ca4e6", "1.15.3.1",
                          "0d2bd18", "1.15.3",
                          "cb6766e", "1.15.2",
                          "fe1d1f8", "1.15.1",
                          "d5ee0df", "1.15",
                          "7398e90", "1.14.8",
                          "4842f6f", "1.14.7",
                          "cc2f481", "1.14.6",
                          "7234a1f", "1.14.5",
                          "5fc29c3", "1.14.4",
                          "f4f5bc6", "1.14.3",
                          "cba6035", "1.14.2",
                          "f1e9e88", "1.14.1",
                          "9ea8e77", "1.14",
                          "4b9a699", "1.14-rc2",
                          "c32990d", "1.14-rc1",
                          "e351ba5", "1.12.6",
                          "933bb1f", "1.12.5",
                          "bd38765", "1.12.4",
                          "bcf1a6f", "1.12.3",
                          "a5d898b", "1.12.2",
                          "a8c4f57", "1.12.1",
                          "a076918", "1.12",
                          "7b1eee8", "1.11",
                          "e321982", "1.11.0-rc1",
                          "dca01e1", "1.10.7",
                          "91602a7", "1.10.6",
                          "13f2f4a", "1.10.5",
                          "035fd0a", "1.10.4",
                          "b7ef532", "1.10.3",
                          "8c848b5", "1.10.2",
                          "9ae093d", "1.10.1",
                          "901e5ea", "1.10",
                          "907ec36", "1.10-rc.3",
                          "231f11e", "1.10-rc.2",
                          "f4a172f", "1.9.16",
                          "70898b3", "1.9.15",
                          "8b927a0", "1.9.14",
                          "a6174db", "1.9.13",
                          "19292ad", "1.9.12",
                          "c1b5a33", "1.9.11",
                          "a7d44f8", "1.9.9",
                          "4752178", "1.9.8.1",
                          "9c6acce", "1.9.8",
                          "4be5782", "1.9.7",
                          "9adad36", "1.9.6",
                          "1faad22", "1.9.5.1",
                          "c18eac4", "1.9.4",
                          "ecb4f89", "1.9.5",
                          "da684b9", "1.8.12",
                          "d0f776f", "1.8.11",
                          "0ce50e3", "1.8.10",
                          "30738f9", "1.8.9",
                          "7960e24", "1.8.8",
                          "bdfece3", "1.8.7",
                          "481c83e", "1.8.6");

if( ! http_can_host_php( port:port ) )
  exit( 0 );

FOUND = FALSE;
url = "/";
res = http_get_cache( port:port, item:url );

# Location: /osticket/scp/login.php
# Location: http://<target>/osticket/
if( res =~ "Location\s*:" ) {
  infos = eregmatch( pattern:"Location\s*:\s*(https?://[^/]+)?(/?[-.a-zA-Z0-9_/]+)", string:res, icase:TRUE );
  if( infos[2] ) {
    url = infos[2];
    if( url !~ "^/" )
      url = "/" + url;
    res = http_get_cache( port:port, item:url );
    if( egrep( pattern:'alt="osTicket', string:res, icase:TRUE ) || res =~ "(P|p)owered by osTicket" || res =~ '<meta name="keywords" content="osTicket' )
      FOUND = TRUE;
  }
} else {
  # eg. <meta http-equiv="refresh" content="0;url=/osticket/index.php">
  if( res =~ '<meta http-equiv="refresh" content=".;\\s*url=' ) {
    infos = eregmatch( pattern:'meta http-equiv="refresh".+(url|URL)=(/[-.a-zA-Z0-9_/]+)', string:res, icase:TRUE );
    if( infos[2] ) {
      url = infos[2];
      res = http_get_cache( port:port, item:url );
      if( egrep( pattern:'alt="osTicket', string:res, icase:TRUE ) || res =~ "(P|p)owered by osTicket" || res =~ '<meta name="keywords" content="osTicket' )
        FOUND = TRUE;
    }
  }
}

if( ! FOUND ) {
  foreach dir( make_list_unique( "/", "/osticket", "/osTicket", http_cgi_dirs( port:port ) ) ) {

    install = dir;
    if( dir == "/" )
      dir = "";

    url = dir + "/open.php";
    res = http_get_cache( port:port, item:url );

    if ( res =~ "HTTP/(2|1.[01]) 404" ) {
      url = dir + "/scp/login.php";
      res = http_get_cache( port:port, item:url );
    }
    # Make sure the page is from osTicket.
    if( egrep( pattern:'alt="osTicket', string:res, icase:TRUE ) || res =~ "(P|p)owered by osTicket" || res =~ '<meta name="keywords" content="osTicket' ) {
      FOUND = TRUE;
      break;
    }
  }
}

if( FOUND ) {
  version = "unknown";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  # For older versions
  pat = "alt=.osTicket STS v(.+) *$";
  matches = egrep( pattern:pat, string:res );
  foreach match( split( matches ) ) {
    match = chomp( match );
    ver = eregmatch( pattern:pat, string:match );
    if( isnull( ver ) )
      break;

    version = ver[1];
    concl = ver[0];

    # 1.2.5, 1.2.7, and 1.3.x all report 1.2; try to distinguish among them.
    if( version == "1.2" ) {
      # 1.3.0 and 1.3.1.
      if( "Copyright &copy; 2003-2004 osTicket.com" >< res ) {
        # nb: 1.3.1 doesn't allow calling 'include/admin_login.php' directly.
        url = dir + "/include/admin_login.php";
        req = http_get( item:url, port:port );
        res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

        if( "<td>Please login:</td>" >< res ) {
          version = "1.3.0";
        } else if ( "Invalid path" >< res ) {
          version = "1.3.1";
        } else {
          version = "unknown";
        }
      # 1.2.5 and 1.2.7
      } else {
        # nb: 1.2.5 has an attachments dir whereas 1.2.7 has attachments.php
        url = dir + "/attachments.php";
        req = http_get( item:url, port:port );
        res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

        if( "You do not have access to attachments" >< res ) {
          version = "1.2.7";
        } else if( res =~ "^HTTP/1\.[01] 404" ) {
          version = "1.2.5";
        }
      }
    }
  }

  if( version == "unknown" ) {
    # osticket.css?9ae093d
    # fabric.min.js?9ae093d
    buf = eregmatch( pattern:"\.(css|js)\?([0-9a-f]{7})", string:res );
    if( ! isnull( buf[2] ) ) {
      version_hash = buf[2];
      foreach hash( keys( lookup_table ) ) {
        if( hash == version_hash ) {
          version = lookup_table[hash];
          concl = "Lookup of Git Hash: " + version_hash;
          break;
        }
      }
    }
  }

  set_kb_item( name:"osticket/detected", value:TRUE );
  set_kb_item( name:"osticket/http/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:osticket:osticket:" );
  if( ! cpe )
    cpe = "cpe:/a:osticket:osticket";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"osTicket", version:version, install:install,
                                            concludedUrl: conclUrl, cpe:cpe, concluded:concl ),
               port:port );
  exit( 0 );
}

exit( 0 );
