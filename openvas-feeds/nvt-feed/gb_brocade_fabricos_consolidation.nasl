# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108335");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-02-15 11:09:51 +0100 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Brocade Fabric OS Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_brocade_fabricos_telnet_detect.nasl", "gb_brocade_fabricos_http_detect.nasl", "gb_brocade_fabricos_snmp_detect.nasl");
  script_mandatory_keys("brocade_fabricos/detected");

  script_xref(name:"URL", value:"http://www.brocade.com/en/products-services/storage-networking/fibre-channel.html");

  script_tag(name:"summary", value:"Consolidation of Brocade Fabric OS detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item( "brocade_fabricos/detected" ) )
  exit( 0 );

detected_version = "unknown";
detected_model = "unknown";

foreach source( make_list( "telnet", "http", "snmp" ) ) {
  version_list = get_kb_list( "brocade_fabricos/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      set_kb_item( name:"brocade_fabricos/version", value:version );
    }
  }

  model_list = get_kb_list( "brocade_fabricos/" + source + "/*/model" );
  foreach model( model_list ) {
    if( model != "unknown" && detected_model == "unknown" ) {
      detected_model = model;
      set_kb_item( name:"brocade_fabricos/model", value:model );
      break;
    }
  }
}

if( detected_version != "unknown" ) {
  os_cpe = "cpe:/o:broadcom:fabric_operating_system:" + detected_version;
  os_name = "Brocade Fabric OS " + detected_version;
} else {
  os_cpe = "cpe:/o:broadcom:fabric_operating_system";
  os_name = "Brocade Fabric OS";
}

if( detected_model != "unknown" ) {
  mod = eregmatch( pattern:"^(Brocade|Dell|IBM_)([0-9A-Z]+)$", string:detected_model );
  if( mod[2] ) {
    hw_name = "Brocade " + mod[2];
    hw_cpe = "cpe:/h:broadcom:brocade_" + tolower( mod[2] );
  } else {
    mod = eregmatch( pattern:"^SilkWorm([0-9A-Z]+)$", string:detected_model );
    if( mod[1] ) {
      hw_name = "Brocade SilkWorm " + mod[1];
      hw_cpe = "cpe:/h:brocade:silkworm_" + tolower( mod[1] );
    } else {
      hw_name = "Brocade " + detected_model;
      hw_cpe = "cpe:/h:brocade:" + tolower( detected_model );
    }
  }
} else {
  hw_name = "Brocade Unknown Model";
  hw_cpe = "cpe:/h:broadcom:switch";
}

os_register_and_report( os:os_name, cpe:os_cpe, desc:"Brocade Fabric OS Detection Consolidation", runs_key:"unixoide" );

location = "/";

if( telnet_port = get_kb_list( "brocade_fabricos/telnet/port" ) ) {
  foreach port( telnet_port ) {
    concluded  = get_kb_item( "brocade_fabricos/telnet/" + port + "/concluded" );
    extra     += '\nTelnet on port ' + port + '/tcp\n';
    if( concluded ) {
      extra += 'Concluded: ' + concluded + '\n';
    }
    register_product( cpe:os_cpe, location:location, port:port, service:"telnet" );
    register_product( cpe:hw_cpe, location:location, port:port, service:"telnet" );
  }
}

if( http_port = get_kb_list( "brocade_fabricos/http/port" ) ) {
  foreach port( http_port ) {
    concluded     = get_kb_item( "brocade_fabricos/http/" + port + "/concluded" );
    concludedUrl  = get_kb_item( "brocade_fabricos/http/" + port + "/concludedUrl" );
    extra        += '\nHTTP(s) on port ' + port + '/tcp\n';
    if( concluded && concludedUrl ) {
      extra += 'Concluded: ' + concluded + ' from URL: ' + concludedUrl + '\n';
    }
    register_product( cpe:os_cpe, location:location, port:port, service:"www" );
    register_product( cpe:hw_cpe, location:location, port:port, service:"www" );
  }
}

if( snmp_port = get_kb_list( "brocade_fabricos/snmp/port" ) ) {
  foreach port( snmp_port ) {
    concluded = get_kb_item( "brocade_fabricos/snmp/" + port + "/concluded" );
    concludedOID = get_kb_item( "brocade_fabricos/snmp/" + port + "/concludedOID" );
    extra += '\nSNMP on port ' + port + '/udp\n';
    if( concluded && concludedOID ) {
      extra += "Version concluded from " + concluded + " via OID: " + concludedOID + '\n';
    }

    concluded_model = get_kb_item( "brocade_fabricos/snmp/" + port + "/model" );
    concludedOID_model = get_kb_item( "brocade_fabricos/snmp/" + port + "/model_oid" );
    if( concluded_model && concludedOID_model ){
      extra += "Model concluded from " + concluded_model + " via OID: " + concludedOID_model + '\n';
    }
    register_product( cpe:os_cpe, location:location, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:hw_cpe, location:location, port:port, service:"snmp", proto:"udp" );
  }
}

report = build_detection_report( app:"Brocade Fabric OS",
                                 version:detected_version,
                                 install:location,
                                 cpe:os_cpe );
report += '\n\n';
report += build_detection_report( app:hw_name,
                                  skip_version:TRUE,
                                  install:location,
                                  cpe:hw_cpe );

if( extra ) {
  report += '\nModel:         ' + concluded_model;
  report += '\n\nDetection methods:\n';
  report += extra;
}

log_message( port:0, data:report );

exit( 0 );
