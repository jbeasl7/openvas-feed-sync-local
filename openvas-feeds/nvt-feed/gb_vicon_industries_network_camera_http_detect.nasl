# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107332");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-07-24 13:53:24 +0200 (Tue, 24 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Vicon Industries Network Camera Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Vicon Industries Network Cameras.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

type_list['0'] = "3 Series / 4 Series";
type_list['5'] = "5 Series";
type_list['7'] = "7 Series";
type_list['8'] = "Sentinel Series";
type_list['9'] = "9 Series";
type_list['A'] = "Alliance-pro";
type_list['D'] = "Alliance-mini";
type_list['M'] = "Alliance-mx";
type_list['P'] = "PTZ";
type_list['R'] = "R5 Series";

port = http_get_port( default:80 );

foreach url( make_list( "/", "/appletvid.html", "/imageset.html", "/basicset.html", "/accessset.html" ) ) {

  res = http_get_cache( item:url, port:port );
  if( ! res )
    continue;

  if( res =~ "Server\s*:\s*IQinVision Embedded" || ( res =~ "<(TITLE|title)>IQ" && ( res =~ '<meta name="author" content="[^>]*IQinVision">' || res =~ '<font color="#[0-9]*">IQ.*</font>' ) ) ) {

    set_kb_item( name:"vicon_industries/network_camera/detected", value:TRUE );
    set_kb_item( name:"vicon_industries/network_camera/http/detected", value:TRUE );
    set_kb_item( name:"vicon_industries/network_camera/http/port", value:port );

    version = "unknown";
    type    = "unknown";

    vers = eregmatch( pattern:"(V|B|Version )(V[0-9.]+)", string:res, icase:FALSE );
    if( vers[2] )
      version = vers[2];

    typerecv = eregmatch( pattern:'IQ(eye)?([0578ADMPR])[^\r\n]*', string:res, icase:FALSE );
    if( type_list[typerecv[2]] )
      type = type_list[typerecv[2]];

    set_kb_item( name:"vicon_industries/network_camera/http/" + port + "/type", value:type );
    set_kb_item( name:"vicon_industries/network_camera/http/" + port + "/version", value:version );
    if( type != "unknown" )
      set_kb_item( name:"vicon_industries/network_camera/http/" + port + "/concluded", value:typerecv[0] );

    exit( 0 );
  }
}

exit( 0 );
