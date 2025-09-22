# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105313");
  script_version("2024-03-19T15:34:11+0000");
  script_tag(name:"last_modification", value:"2024-03-19 15:34:11 +0000 (Tue, 19 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-07-03 10:42:08 +0200 (Fri, 03 Jul 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Fortinet FortiOS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Fortinet devices running FortiOS.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:443 );

# TBD: In the future we could also make a list out of this and use if via a "in_array()" check later below.
hashes = '58b2ac766d43383c3040216930c5faf2
          3fb77230f7ff552da7599632eae9dc8d
          3955ddaf1229f63f94f4a20781b3ade4
          2719cca465341edf55be52939058893e
          5ed607103738fa9c2788e0f51567bdb8
          8f5018acd4cdeb6a6122e51006a53e86
          77759f22e8c2a847f655dba3d6013555
          29f7a3d0bc4da0e0a636e31e6a670d31
          7c1fd3cd595862f26d1460037cbec76a
          d3b30398ae57327dfdae2293d7da6f08
          fe72969c26f1fe2ea2130d5a3222219e';

urls = make_list( "/favicon.ico",
                  "/images/logon_merge.gif",
                  "/favicon/favicon-16x16.png",
                  "/resource/images/logon_t.gif",
                  "/resource/images/logon.gif",
                  "/customviews/image/login_bg/",
                  "/images/login_top.gif",
                  "/theme1/images/logo.gif",
                  "/images/logo.gif" );

foreach url( urls ) {

  req = http_get( port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req,
                                  content_type_body_only:"^Content-Type\s*:\s*(text|image)/" );
  if( ! res || res !~ "^HTTP/(2|1\.[01]) 200" )
    continue;

  if( ! body = http_extract_body_from_response( data:res ) )
    continue;

  hash = hexstr( MD5( body ) );

  if( hash && hash >< hashes ) {

    version = "unknown";
    install = "/";

    # KB keys if an advisory states that e.g. "FortiOS" is affected without specifying which
    # products running FortiOS and an active check via e.g. HTTP is possible.
    set_kb_item( name:"fortinet/fortios_product/detected", value:TRUE );
    set_kb_item( name:"fortinet/fortios_product/http/detected", value:TRUE );
    set_kb_item( name:"fortinet/fortios_product/" + port + "/http/detected", value:TRUE );

    cpe = "cpe:/o:fortinet:fortios";

    os_register_and_report( os:"Fortinet FortiOS", cpe:cpe, banner_type:"HTTP banner", port:port,
                            desc:"Fortinet FortiOS Detection (HTTP)", runs_key:"unixoide" );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Fortinet device running FortiOS",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:http_report_vuln_url( port:port, url:url, url_only:TRUE ),
                                              concluded:"MD5 hash: " + hash ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
