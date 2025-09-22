# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113595");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2019-11-29 11:53:55 +0200 (Fri, 29 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Embedthis GoAhead Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Embedthis GoAhead embedded web
  server.");

  script_xref(name:"URL", value:"https://www.embedthis.com/goahead/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );

# Server: GoAhead-Webs
# Server: GoAhead-Webs/2.5.0 PeerSec-MatrixSSL/3.4.2-OPEN
if( concl = egrep( string:banner, pattern:"^Server\s*:\s*GoAhead-Webs", icase:TRUE ) ) {
  concluded = "  " + chomp( concl );
  found = TRUE;
  conclUrl = "  " + http_report_vuln_url( port:port, url:"/", url_only:TRUE );
}

# nb: As the product seems to be customizable (e.g. hiding the banner) various fingerprinting
# methods are used here.
foreach dir( make_list( "/cgi-bin", "/cgi" ) ) {

  # nb:
  # - This was used in / via for "Fingerprinting":
  #   - https://github.com/1337g/CVE-2017-17562/blob/master/CVE-2017-17562.py
  #   - 2017/gb_goahead_rce_vuln.nasl
  # - If ever required we could also changes this to a dynamically created random string
  url = dir + "/c8fed00eb2e87f1cee8e90ebbe870c190ac3848c";
  req = http_get( port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req );

  # <p>CGI process file does not exist</p></body></html>
  if( res && ( concl = eregmatch( string:res, pattern:"<[^>]+>CGI process file does not exist<[^>]+>", icase:FALSE ) ) ) {

    if( concluded )
      concluded += '\n';
    concluded += "  " + chomp( concl[0] );

    if( conclUrl )
      conclUrl += '\n';
    conclUrl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    found = TRUE;
    break;
  }
}

url = "/favicon.ico";
req = http_get( port:port, item:url );
md5res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
if( ! isnull( md5res ) ) {

  md5 = hexstr( MD5( md5res ) );
  if( md5 == "7daa7cff4bdb6a6b4c33aeca089debff" ) {

    if( concluded )
      concluded += '\n';
    concluded += "  Favicon hash: " + md5;

    if( conclUrl )
      conclUrl += '\n';
    conclUrl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    found = TRUE;
  }
}

foreach url( make_list( "/vt-test-non-existent.html", "/vt-test/vt-test-non-existent.html" ) ) {

  res = http_get_cache( item:url, port:port, fetch404:TRUE );

  if( res =~ "^HTTP/1\.[01] 404" &&
      ( concl1 = eregmatch( string:res, pattern:"<head><title>Document Error: Not Found</title></head>", icase:FALSE ) ) &&
      ( concl2 = eregmatch( string:res, pattern:"<h[0-9]+>Access Error: Not Found</h[0-9]+>", icase:FALSE ) )
    ) {

    if( concluded )
      concluded += '\n';
    concluded += "  " + concl1[0];
    concluded += '\n';
    concluded += "  " + concl2[0];

    if( conclUrl )
      conclUrl += '\n';
    conclUrl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    found = TRUE;
    break;
  }
}

# nb: It seems both "/goform" and "/goforms" exists
foreach url( make_list( "/goform/vt-test-non-existent.html", "/goforms/vt-test-non-existent.html" ) ) {

  res = http_get_cache( item:url, port:port, fetch404:TRUE );

  if( res =~ "^HTTP/1\.[01] [0-9]{3}" &&

      # With "200 Data follows" status code:
      #
      # <html><head><title>Document Error: Data follows</title></head>
      #     <body><h2>Access Error: Data follows</h2>
      #     <p>Form vt-test-non-existent.html is not defined</p></body></html>
      #
      # With "404 Site or Page Not Found" status code:
      #
      # <html><head><title>Document Error: Site or Page Not Found</title></head>
      #     <body><h2>Access Error: Site or Page Not Found</h2>
      #     <p>Form is not defined</p></body></html>

      ( concl1 = eregmatch( string:res, pattern:"<(title|h[0-9]+)>(Document|Access) Error: [^<]+</(title|h[0-9]+)>", icase:FALSE ) ) &&
      ( concl2 = eregmatch( string:res, pattern:"<p>Form ([^ ]+ )?is not defined</p>", icase:FALSE ) )
    ) {

    if( concluded )
      concluded += '\n';
    concluded += "  " + concl1[0];
    concluded += '\n';
    concluded += "  " + concl2[0];

    if( conclUrl )
      conclUrl += '\n';
    conclUrl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    found = TRUE;
    break;
  }
}

if( found ) {

  set_kb_item( name:"embedthis/goahead/detected", value:TRUE );
  set_kb_item( name:"embedthis/goahead/http/detected", value:TRUE );

  location = "/";
  version = "unknown";

  vers = eregmatch( string:banner, pattern:"GoAhead-Webs/([0-9.]+)", icase:TRUE );
  if( ! isnull( vers[1] ) )
    version = vers[1];

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:embedthis:goahead:" );
  if( ! cpe )
    cpe = "cpe:/a:embedthis:goahead";

  register_product( cpe:cpe, location:location, port:port, service:"www" );

  log_message( data:build_detection_report( app: "Embedthis GoAhead", version:version, install:location,
                                            cpe:cpe, concluded:concluded, concludedUrl:conclUrl ),
               port:port );
  exit( 0 );
}

exit( 0 );
