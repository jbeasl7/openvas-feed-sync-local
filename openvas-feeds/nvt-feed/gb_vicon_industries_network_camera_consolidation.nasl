# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107335");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-07-25 17:21:25 +0200 (Wed, 25 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Vicon Industries Network Camera Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_vicon_industries_network_camera_snmp_detect.nasl", "gb_vicon_industries_network_camera_telnet_detect.nasl",
                      "gb_vicon_industries_network_camera_http_detect.nasl");
  script_mandatory_keys("vicon_industries/network_camera/detected");

  script_tag(name:"summary", value:"Consolidation of Vicon Industries Network Camera detections.");

  script_tag(name:"insight", value:"The exposed Part Number of the device is referenced to identify the Camera Series.

  Example: IQ A 1 2 S I - B2

  A -> Camera Type: '0' covers 3/4 Series, '5' covers 5 Series, '7' covers 7 Series, '8' covers Sentinel Series,
  'A' covers Alliance-pro, 'D' covers Aliance-mini, 'M' covers Alliance-mx, 'P' covers PTZ, 'R' covers R5 Series etc.

  1 -> Revision / Architecture: '0' or '1' covers Original, '2' covers MJPEG w / VGA H.264, '3' covers Full Res H.264,
  '4' covers Basic Architecture, '5' covers Day / Night, '6' covers Full Res H.264 / Focus etc.

  2 -> Resolution: '0' covers VGA / HD 480p, '1' covers 1.3 MP / HD 720p, '2' covers 2.0 MP/HD 1080p, '3' covers 3 MP,
  '5' covers 5 MP etc.

  S -> Option 1: 'N' covers Day / Night, 'S' covers Standard etc.

  I -> Option 2: 'E' covers Exterior, 'I' covers Interior, 'V' covers Vandal Resistant,
  'X' covers Extreme Temp. etc.

  B2 -> Lens Kits: 'NL' covers No Lens");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item( "vicon_industries/network_camera/detected" ) )
  exit( 0 );

detected_version = "unknown";
detected_type    = "unknown";

foreach source( make_list( "snmp", "telnet", "http" ) ) {

  version_list = get_kb_list( "vicon_industries/network_camera/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      set_kb_item( name:"vicon_industries/network_camera/version", value:version );
      break;
    }
  }

  type_list = get_kb_list( "vicon_industries/network_camera/" + source + "/*/type" );
  foreach type( type_list ) {
    if( type != "unknown" && detected_type == "unknown" ) {
      detected_type = type;
      set_kb_item( name:"vicon_industries/network_camera/type", value:type );
      break;
    }
  }
}

if( detected_type != "unknown" ) {
  hw_name = "Vicon Industries " + detected_type + " Network Camera";
  os_name = hw_name + " Firmware";
  detected_type = str_replace( string:type, find:" ", replace:"_");
  hw_cpe   = "cpe:/h:vicon_industries:network_camera_" + tolower( detected_type );
  os_cpe   = "cpe:/o:vicon_industries:network_camera_" + tolower( detected_type ) + "_firmware";
} else {
  hw_name = "Vicon Industries Unknown Model Network Camera";
  os_name = hw_name + " Firmware";
  hw_cpe = "cpe:/h:vicon_industries:network_camera_unknown_model";
  os_cpe = "cpe:/o:vicon_industries:network_camera_unknown_model_firmware";
}

if( detected_version != "unknown" )
  os_cpe += ":" + detected_version;

location = "/";

if( snmp_ports = get_kb_list( "vicon_industries/network_camera/snmp/port" ) ) {
  foreach port( snmp_ports ) {
    concluded = get_kb_item( "vicon_industries/network_camera/snmp/" + port + "/concluded" );
    extra += "SNMP on port " + port + '/udp\n';
    if( concluded )
      extra += 'Concluded from SNMP sysDescr OID: ' + concluded + '\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:os_cpe, location:location, port:port, service:"snmp", proto:"udp" );
  }
}

if( telnet_ports = get_kb_list( "vicon_industries/network_camera/telnet/port" ) ) {
  foreach port( telnet_ports ) {
    concluded = get_kb_item( "vicon_industries/network_camera/telnet/" + port + "/concluded" );
    extra += "Telnet on port " + port + '/tcp\n';
    if( concluded ) {
      extra += 'Concluded: ' + concluded + '\n';
    }
    register_product( cpe:hw_cpe, location:location, port:port, service:"telnet" );
    register_product( cpe:os_cpe, location:location, port:port, service:"telnet" );
  }
}

if( http_ports = get_kb_list( "vicon_industries/network_camera/http/port" ) ) {
  foreach port( http_ports ) {
    concluded = get_kb_item( "vicon_industries/network_camera/http/" + port + "/concluded" );
    extra += "HTTP(s) on port " + port + '/tcp\n';
    if( concluded )
      extra += 'Concluded: ' + concluded + '\n';

    register_product( cpe:hw_cpe, location:location, port:port, service:"www" );
    register_product( cpe:os_cpe, location:location, port:port, service:"www" );
  }
}

os_register_and_report( os:os_name, cpe:os_cpe, desc:"Vicon Industries Network Camera Detection Consolidation", runs_key:"unixoide" );

report = build_detection_report( app:os_name,
                                 version:detected_version,
                                 install:location,
                                 cpe:os_cpe );
report += '\n\n' + build_detection_report( app:hw_name,
                                           install:location,
                                           cpe:hw_cpe,
                                           skip_version:TRUE );
if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message( port:0, data:report );

exit( 0 );
