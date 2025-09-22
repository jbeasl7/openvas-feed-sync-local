# SPDX-FileCopyrightText: 2006 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20285");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("HP Integrated Lights-Out (iLO) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2006 David Maciejak");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of HP Integrated Lights-Out (iLO)
  devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:443 );
r = http_get_cache( item:"/", port:port );
if( ! r )
  exit( 0  );

if ((r =~ "(<title>HP iLO Login</title>|<title>iLO [0-9]+</title>)" &&
     "Hewlett-Packard Development Company" >< r) ||
    ("HP Integrated Lights-Out" >< r &&
     egrep(pattern: "Copyright .+ Hewlett-Packard Development Company", string: r)) ||
    ("<title>HP Remote Insight<" >< r && egrep(pattern: "Hewlett-Packard Development Company", string: r)) ||
    (r =~ ">HP Integrated Lights-Out [0-9]+ Login<" && r =~ "Copyright.*Hewlett Packard Enterprise Development") ||
    "Server: HP-iLO-Server" >< r || "Server: HPE-iLO-Server" >< r ||
    ("iLO.getSVG" >< r && "iLO.getCookie" >< r) ||
    ("EVT_ILO_RESET_PULSE" >< r && "iLOGlobal" >< r)) {

  fw_vers  = "unknown";
  ilo_vers = "unknown";
  sso      = 0;
  install  = "/";

  url = "/xmldata?item=All";
  req = http_get( item:url, port:port );
  buf = http_send_recv( port:port, data:req, bodyonly:TRUE );

  if( "Integrated Lights-Out" >< buf ) {

    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    # <FWRI>2.53</FWRI>
    fw_version = eregmatch( pattern:"<FWRI>([^<]+)</FWRI>", string:buf );
    if( ! isnull( fw_version[1] ) )
      fw_vers = fw_version[1];

    # <PN>Integrated Lights-Out 4 (iLO 4)</PN>
    if( "<PN>Integrated Lights-Out (iLO)</PN>" >< buf ) {
      ilo_vers = 1;
    } else {
      ilo_version = eregmatch( pattern:"<PN>Integrated Lights-Out ([0-9]+) [^<]+</PN>", string:buf );
      if( ! isnull( ilo_version[1] ) )
        ilo_vers = int( ilo_version[1] );
    }

   # <SSO>0</SSO>
    _sso = eregmatch( pattern:"<SSO>(0|1)</SSO>", string:buf );
    if( ! isnull( _sso[1] ) ) {
      sso = int( _sso[1] );
      extra = "SSO Status: " + _sso[0];
    }
  }

  if( ilo_vers == "unknown" && r =~ "<title>iLO [0-9]+</title>" ) {
    ilo_version = eregmatch( pattern:"<title>iLO ([0-9]+)</title>", string:r );
    if( ! isnull( ilo_version[1] ) )
      ilo_vers = int( ilo_version[1] );
  }

  if( fw_vers == "unknown" || ilo_vers == "unknown" ) {

    url = "/json/login_session";
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( '{"secjmp' >< buf ) {

      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

      if( fw_vers == "unknown" ) {
        # "version":"2.53"
        fw_version = eregmatch( pattern:'version":"([^"]+)"', string:buf );
        if( ! isnull( fw_version[1] ) )
          fw_vers = fw_version[1];
      }

      if( ilo_vers == "unknown" ) {
        # "PRODGEN":"iLO 4",
        ilo_version = eregmatch( pattern:'"PRODGEN":"iLO ([0-9]+)",', string:buf );
        if( ! isnull( ilo_version[1] ) )
          ilo_vers = int( ilo_version[1] );
      }
    }
  }

  cpe = "cpe:/o:hp:integrated_lights-out";

  if( ilo_vers != "unknown" ) {
    app_name = "HP Integrated Lights-Out Generation " + ilo_vers + " Firmware";
    concluded += ilo_version[0];
    cpe += "_" + ilo_vers + "_firmware";
  } else {
    app_name = "HP Integrated Lights-Out Unknown Generation Firmware";
    cpe += "_unknown_firmware";
  }

  if( fw_vers != "unknown" ) {
    if( concluded )
      concluded += '\n';
    concluded += fw_version[0];
    cpe += ':' + fw_vers;
  }

  set_kb_item( name:"www/" + port + "/HP_ILO/fw_version", value:fw_vers );
  set_kb_item( name:"www/" + port + "/HP_ILO/ilo_version", value:ilo_vers );
  set_kb_item( name:"www/" + port + "/HP_ILO/sso", value:sso );
  set_kb_item( name:"hp/ilo/detected", value:TRUE );

  os_register_and_report( os:app_name, cpe:cpe, desc:"HP Integrated Lights-Out (iLO) Detection", runs_key:"unixoide" );

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  log_message( data:build_detection_report( app:app_name,
                                            version:fw_vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded,
                                            concludedUrl:conclUrl,
                                            extra:extra ),
               port:port );
}

exit( 0 );
