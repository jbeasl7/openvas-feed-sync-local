# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141019");
  script_version("2024-11-27T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-11-27 05:05:40 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-04-24 09:33:03 +0700 (Tue, 24 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sonos Device/OS/App Detection (UPnP, TCP)");

  script_tag(name:"summary", value:"UPnP based detection of Sonos devices, Sonos OS and
  application.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_upnp_tcp_detect.nasl");
  script_require_ports("Services/www", 1400);
  script_mandatory_keys("upnp/tcp/port");

  script_xref(name:"URL", value:"https://www.sonos.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("cpe.inc");
include("os_func.inc");

if( ! ports = get_kb_list( "upnp/tcp/port" ) )
  exit( 0 );

location = "/";

foreach port( ports ) {

  if( ! vendor = get_kb_item( "upnp/tcp/" + port + "/device/manufacturer" ) )
    continue;

  if( "Sonos" >< vendor ) {
    concluded = '\n    - Manufacturer: ' + vendor;

    upnp_loc = get_kb_item( "upnp/tcp/" + port + "/location" );
    if( upnp_loc )
      conclUrl = http_report_vuln_url( port:port, url:upnp_loc, url_only:TRUE );

    model_name = get_kb_item( "upnp/tcp/" + port + "/device/modelName" );
    if( model_name ) {
      concluded += '\n    - Model name:   ' + model_name;
      # Sonos Bridge
      # Sonos BOOST
      info = split( model_name, sep:" ", keep:FALSE );
      model = info[1];
      if( model )
        set_kb_item( name:"sonos/model", value:model );
    }

    software_version = get_kb_item( "upnp/tcp/" + port + "/device/softwareVersion" );
    if( software_version )
      concluded += '\n    - Build Number: ' + software_version;

    display_version = get_kb_item( "upnp/tcp/" + port + "/device/displayVersion" );
    if( display_version )
      concluded += '\n    - Version:      ' + display_version;

    software_generation = get_kb_item ( "upnp/tcp/" + port + "/device/softwareGeneration" );
    if( software_generation == 2 ) {
      app_app = "Sonos S2 App";
      app_cpe = build_cpe( value:display_version, exp:"^([0-9.-]+)", base:"cpe:/a:sonos:s2:" );
      if( ! app_cpe )
        app_cpe = "cpe:/a:sonos:s2";
    } else {
      software_generation = 1;
      app_app = "Sonos S1 App";
      app_cpe = build_cpe( value:display_version, exp:"^([0-9.-]+)", base:"cpe:/a:sonos:s1:" );
      if( ! app_cpe )
        app_cpe = "cpe:/a:sonos:s1";
    }

    concluded += '\n    - App Gen:      ' + software_generation;

    cpe_model = tolower( model );

    if( ":" >< cpe_model )
      cpe_model = str_replace( string:cpe_model, find:":", replace:"%3a" );

    hw_app = "Sonos " + model + " Device";
    hw_cpe = "cpe:/h:sonos:" + cpe_model ;
    os_app = "Sonos " + model + " Firmware";
    os_cpe = "cpe:/o:sonos:" + cpe_model + "_firmware:" + software_version;

    set_kb_item( name:"sonos/detected", value:TRUE );
    set_kb_item( name:"sonos/upnp/detected", value:TRUE );
    set_kb_item( name:"sonos/upnp/port", value:port );

    os_register_and_report( os:os_app, cpe:os_cpe, port:port, desc:"Sonos Device/OS/App Detection (UPnP, TCP)", runs_key:"unixoide" );

    register_product( cpe:hw_cpe, location:location, port:port, service:"upnp" );
    register_product( cpe:os_cpe, location:location, port:port, service:"upnp" );
    register_product( cpe:app_cpe, location:location, port:port, service:"upnp" );

    report = build_detection_report( app:os_app,
                                     version:software_version,
                                     install:location,
                                     cpe:os_cpe );
    report += '\n\n';
    report += build_detection_report( app:hw_app,
                                      skip_version:TRUE,
                                      install:location,
                                      cpe:hw_cpe );
    report += '\n\n';
    report += build_detection_report( app:app_app,
                                      version:display_version,
                                      install:location,
                                      cpe:app_cpe );

    report += '\n\nDetected via UPnP on port ' + port + "/tcp";
    report += '\n  Concluded from:' + concluded;

    if( conclUrl )
      report += '\n  from URL:\n    ' + conclUrl;

    log_message( port:port, data:chomp( report ) );
  }
}

exit( 0 );
