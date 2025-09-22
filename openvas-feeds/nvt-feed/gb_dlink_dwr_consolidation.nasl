# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171565");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-06-30 12:46:41 +0000 (Mon, 30 Jun 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("D-Link DWR Device Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_dlink_dwr_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_dlink_devices_upnp_detect.nasl");
  script_mandatory_keys("d-link/dwr/detected");

  script_tag(name:"summary", value:"Consolidation of D-Link DWR (Router) devices detections.");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item( "d-link/dwr/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...
detection_methods = "";
fw_version = "unknown";
hw_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source( make_list( "http", "snmp", "upnp" ) ) {
  version_list = get_kb_list( "d-link/dwr/" + source + "/*/fw_version" );
  foreach version( version_list ) {
    if( version != "unknown" && fw_version == "unknown" ) {
      fw_version = version;
      break;
    }
  }

  hw_version_list = get_kb_list( "d-link/dwr/" + source + "/*/hw_version" );
  foreach version( hw_version_list ) {
    if( version != "unknown" && hw_version == "unknown" ) {
      hw_version = version;
      break;
    }
  }

  model_list = get_kb_list( "d-link/dwr/" + source + "/*/model" );
  foreach model( model_list ) {
    if( model != "unknown" && detected_model == "unknown" ) {
      detected_model = model;
      break;
    }
  }
}

os_app = "D-Link DWR";
os_cpe = "cpe:/o:dlink:dwr";
hw_app = "D-Link DWR";
hw_cpe = "cpe:/h:dlink:dwr";

if( detected_model != "unknown" ) {
  cpe_model = tolower( detected_model );
  if( "/" >< cpe_model )
    cpe_model = str_replace( string:cpe_model, find:"/", replace:"%2f" );
  os_app += "-" + detected_model + " Firmware";
  os_cpe += "-" + cpe_model + "_firmware";
  hw_app += "-" + detected_model + " Device";
  hw_cpe += "-" + cpe_model;
  set_kb_item( name:"d-link/dwr/model", value:detected_model );
} else {
  os_app += " Unknown Model Firmware";
  os_cpe += "-unknown_model_firmware";
  hw_app += " Unknown Model Device";
  hw_cpe += "-unknown_model";
}

if( fw_version != "unknown" ) {
  os_cpe += ":" + fw_version;
  set_kb_item( name:"d-link/dwr/fw_version", value:fw_version );
}

if( hw_version != "unknown" ) {
  hw_cpe += ":" + tolower( hw_version );
  set_kb_item( name:"d-link/dwr/hw_version", value:hw_version );
}

register_port = 0;

if( http_ports = get_kb_list( "d-link/dwr/http/port" ) ) {
  foreach port( http_ports ) {
    detection_methods += '\n- HTTP(s) on port ' + port + '/tcp\n';
    fw_concluded = get_kb_item( "d-link/dwr/http/" + port + "/fw_concluded" );
    fw_conclurl = get_kb_item( "d-link/dwr/http/" + port + "/fw_conclurl" );
    if( fw_concluded && fw_conclurl )
      detection_methods += '  Firmware concluded:\n    ' + fw_concluded + '\n  from URL(s):\n    ' + fw_conclurl + '\n';
    else if( fw_concluded )
      detection_methods += '  Firmware concluded:\n    ' + fw_concluded + '\n';

    hw_concluded = get_kb_item( "d-link/dwr/http/" + port + "/hw_concluded" );
    hw_conclurl = get_kb_item( "d-link/dwr/http/" + port + "/hw_conclurl" );
    if( hw_concluded && hw_conclurl )
      detection_methods += '  Hardware version concluded:\n    ' + hw_concluded + '\n  from URL(s):\n    ' + hw_conclurl + '\n';
    else if( hw_concluded )
      detection_methods += '  Hardware version concluded:\n    ' + hw_concluded + '\n';

    register_port = port;
    register_product( cpe:hw_cpe, location:location, port:register_port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:register_port, service:"www" );
  }
}

if( upnp_ports = get_kb_list( "d-link/dwr/upnp/port" ) ) {
  foreach port( upnp_ports ) {
    detection_methods += '\n- UPnP on port ' + port + '/tcp\n';

    concluded = get_kb_item( "d-link/dwr/upnp/" + port + "/concluded" );
    if ( concluded ) {
      detection_methods += '  Concluded:' + concluded;
      concludedurl = get_kb_item( "d-link/dwr/upnp/" + port + "/concludedUrl" );
      if ( concludedurl )
        detection_methods += '\n  from URL:\n    ' + concludedurl;
    }
  }
  # nb: uPnP might point to a different port than the registered one
  if( ! register_port || register_port >< port ) {
    register_product( cpe:hw_cpe, location:location, port:port, service:"upnp" );
    register_product( cpe:os_cpe, location:location, port:port, service:"upnp" );
  }
}

# nb: For cases when a generic key is needed
set_kb_item( name:"d-link/detected", value:TRUE );

os_register_and_report( os:os_app, cpe:os_cpe, port:port, desc:"D-Link DWR Device Detection Consolidation", runs_key:"unixoide" );

report  = build_detection_report( app:os_app,
                                  version:fw_version,
                                  install:location,
                                  cpe:os_cpe );
report += '\n\n';
report += build_detection_report( app:hw_app,
                                  version:hw_version,
                                  install:location,
                                  cpe:hw_cpe );

if( detection_methods )
  report += '\n\nDetection methods:\n' + detection_methods;

log_message( port:0, data:chomp( report ) );

exit( 0 );
