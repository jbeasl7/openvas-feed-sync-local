# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107046");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-09-12 13:18:59 +0200 (Mon, 12 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("phpIPAM Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of phpIPAM.");

  script_xref(name:"URL", value:"https://phpipam.net/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", "/phpipam", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/?page=login";
  buf = http_get_cache( port:port, item:url );

  if( isnull( buf ) )
    continue;

  if( buf =~ "^HTTP/1\.[01] 200" && "phpIPAM IP address management" >< buf ) {

    version = "unknown";

    conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    #<a href="http://phpipam.net">phpIPAM IP address management [v1.3]</a>
    #</span>
    #phpIPAM IP address management [v1.1] rev010
    #<span
    vers = eregmatch( pattern:"phpIPAM IP address management \[v([0-9.]+)\]( rev([0-9]+))?", string:buf );

    if( vers[1] && vers[3] )
      version = vers[1] + "." + vers[3];
    else if( vers[1] )
      version = vers[1];

    set_kb_item( name:"phpipam/" + port + "/version", value:version );
    set_kb_item( name:"phpipam/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:phpipam:phpipam:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:phpipam:phpipam";

    register_product( cpe:cpe, location:install, port:port, service:"www" );
    log_message( data:build_detection_report( app:"phpIPAM",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0],
                                              concludedUrl:conclurl ),
                                              port:port );

    exit( 0 );
  }
}

exit( 0 );
