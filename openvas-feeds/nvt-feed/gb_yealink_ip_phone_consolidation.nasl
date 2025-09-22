# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113281");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-10-30 13:19:10 +0100 (Tue, 30 Oct 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Yealink IP Phone Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_yealink_ip_phone_sip_detect.nasl",
                      "gb_yealink_ip_phone_http_detect.nasl");
  script_mandatory_keys("yealink/ipphone/detected");

  script_tag(name:"summary", value:"Consolidation of Yealink IP Phone detections.");

  script_xref(name:"URL", value:"https://www.yealink.com/en/product-list/ip-phone");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item( "yealink/ipphone/detected" ) )
  exit( 0 );

detected_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source( make_list( "sip", "http" ) ) {
  version_list = get_kb_list( "yealink/ipphone/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list( "yealink/ipphone/" + source + "/*/model" );
  foreach model( model_list ) {
    if( model != "unknown" && detected_model == "unknown" ) {
      detected_model = model;
      set_kb_item( name: "yealink/ipphone/model", value: detected_model );
      break;
    }
  }
}

if( detected_model != "unknown" ) {
  os_name = "Yealink IP Phone " + detected_model + " Firmware";
  hw_name = "Yealink IP Phone " + detected_model;
  hw_cpe = "cpe:/h:yealink:" + tolower(detected_model);
} else {
  os_name = "Yealink IP Phone Unknown Model Firmware";
  hw_name = "Yealink IP Phone Unknown Model";
  hw_cpe = "cpe:/h:yealink:voip_phone";
}

os_cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:yealink:voip_phone_firmware:" );
if( ! os_cpe )
  os_cpe = "cpe:/o:yealink:voip_phone_firmware";

os_register_and_report( os: os_name, cpe: os_cpe, desc: "Yealink IP Phone Detection Consolidation", runs_key: "unixoide" );

if( http_ports = get_kb_list( "yealink/ipphone/http/port" ) ) {
  foreach port( http_ports ) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item( "yealink/ipphone/http/" + port + "/concluded" );
    if( concluded )
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    conclUrl = get_kb_item( "yealink/ipphone/http/" + port + "/concludedUrl" );
    if( conclUrl )
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product( cpe: os_cpe, location: location, port: port, service: "www" );
    register_product( cpe: hw_cpe, location: location, port: port, service: "www" );
  }
}

if( sip_ports = get_kb_list( "yealink/ipphone/sip/port" ) ) {
  foreach port( sip_ports ) {
    proto = get_kb_item( "yealink/ipphone/sip/" + port + "/proto" );
    extra += 'SIP on port ' + port + '/' + proto + '\n';

    concluded = get_kb_item( "yealink/ipphone/sip/" + port + "/concluded" );
    if( concluded )
      extra += "  SIP Banner: " + concluded + '\n';

    register_product( cpe: hw_cpe, location: location, port: port, service: "sip", proto: proto );
    register_product( cpe: os_cpe, location: location, port: port, service: "sip", proto: proto );
  }
}

report  = build_detection_report( app: os_name, version: detected_version, install: location, cpe: os_cpe );
report += '\n\n';
report += build_detection_report( app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe );

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message( port: 0, data: chomp( report ) );

exit(0);
