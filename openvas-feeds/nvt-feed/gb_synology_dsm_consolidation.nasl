# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170202");
  script_version("2024-09-16T09:36:54+0000");
  script_tag(name:"last_modification", value:"2024-09-16 09:36:54 +0000 (Mon, 16 Sep 2024)");
  script_tag(name:"creation_date", value:"2022-10-25 11:21:01 +0000 (Tue, 25 Oct 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology NAS / DiskStation Manager (DSM) Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_synology_dsm_http_detect.nasl",
                      "gb_synology_dsm_srm_mdns_detect.nasl",
                      "gb_synology_dsm_srm_upnp_detect.nasl",
                      "gb_synology_dsm_ssh_login_detect.nasl",
                      "gb_synology_dsm_snmp_detect.nasl",
                      "gb_synology_dsm_findhostd_detect.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Consolidation of Synology NAS devices, DiskStation Manager
  (DSM) OS and application detections.");

  script_xref(name:"URL", value:"https://www.synology.com/en-us/dsm");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");

if( ! get_kb_item( "synology/dsm/detected" ) )
  exit( 0 );

detected_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source( make_list( "ssh-login", "findhostd", "http", "upnp", "mdns", "snmp" ) ) {
  version_list = get_kb_list( "synology/dsm/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list( "synology/dsm/" + source + "/*/model" );
  foreach model( model_list ) {
    if( model != "unknown" && detected_model == "unknown" ) {
      detected_model = model;
      break;
    }
  }
}

if( detected_model != "unknown" ) {
  os_app = "Synology DSM " + detected_model + " Firmware";
  os_cpe = "cpe:/o:synology:" + tolower( detected_model ) + "_firmware";
  hw_app = "Synology NAS " + detected_model + " Device";
  hw_cpe = "cpe:/h:synology:" + tolower( detected_model );
} else {
  os_app = "Synology NAS Unknown Model Firmware";
  os_cpe = "cpe:/o:synology:unknown_model_firmware";
  hw_app = "Synology NAS Unknown Model Device";
  hw_cpe = "cpe:/h:synology:unknown_model";
}

if( detected_version != "unknown" )
  os_cpe += ":" + detected_version;

# nb: since NVD registers this as multiple CPEs, used this a: for model agnostic registration
cpe = build_cpe( value:detected_version, exp:"^([0-9.-]+)", base:"cpe:/a:synology:diskstation_manager:" );
if( ! cpe )
  cpe = "cpe:/a:synology:diskstation_manager";

os_register_and_report( os:"Synology DiskStation Manager", cpe:os_cpe, port:0,
                        desc:"Synology NAS / DiskStation Manager (DSM) Detection Consolidation", runs_key:"unixoide" );

registered = FALSE;
register_port = 0;

if( http_ports = get_kb_list( "synology/dsm/http/port" ) ) {
  foreach port( http_ports ) {

    detection_methods += '\n\nHTTP(s) on port ' + port + "/tcp";

    concluded    = get_kb_item( "synology/dsm/http/" + port + "/concluded" );
    concludedUrl = get_kb_item( "synology/dsm/http/" + port + "/concludedUrl" );
    if( concluded && concludedUrl )
      detection_methods += '\n  Concluded:' + concluded + '\n  from URL(s):\n' + concludedUrl;
    else if( concludedUrl )
      detection_methods += '\n  Concluded from URL(s):\n' + concludedUrl;

    error = get_kb_item( "synology/dsm/http/" + port + "/error" );
    if( error )
      info = error;

    register_port = port;
    registered = TRUE;
  }
}

if( ssh_login_ports = get_kb_list( "synology/dsm/ssh-login/port" ) ) {
  foreach port( ssh_login_ports ) {
    detection_methods += '\n\nSSH login on port ' + port + "/tcp";

    concludedVers = get_kb_item( "synology/dsm/ssh-login/" + port + "/concludedVers" );
    if( concludedVers )
      detection_methods += '\n  Version concluded from:\n' + concludedVers;

    concludedMod = get_kb_item( "synology/dsm/ssh-login/" + port + "/concludedMod" );
    if( concludedMod )
      detection_methods += '\n  Model concluded from:\n' + concludedMod;

    register_product( cpe:hw_cpe, location:location, port:port, service:"ssh-login" );
    register_product( cpe:os_cpe, location:location, port:port, service:"ssh-login" );
    register_product( cpe:cpe, location:location, port:port, service:"ssh-login" );
  }
}

if( snmp_ports = get_kb_list( "synology/dsm/snmp/port" ) ) {
  foreach port( snmp_ports ) {
    detection_methods += '\n\nSNMP on port ' + port + "/udp";

    concludedVers = get_kb_item( "synology/dsm/snmp/" + port + "/concludedVers" );
    concludedVersOID = get_kb_item( "synology/dsm/snmp/" + port + "/concludedVersOID" );
    if( concludedVers && concludedVersOID )
      detection_methods += '\n  Version concluded from: "' + concludedVers + '" via OID: "' +
                           concludedVersOID + '"';

    concludedMod = get_kb_item( "synology/dsm/snmp/" + port + "/concludedMod" );
    concludedModOID = get_kb_item( "synology/dsm/snmp/" + port + "/concludedModOID" );
    if( concludedMod && concludedModOID )
      detection_methods += '\n  Model concluded from: "' + concludedMod + '" via OID: "' +
                           concludedModOID + '"';

    register_product( cpe:hw_cpe, location:location, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:os_cpe, location:location, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:cpe, location:location, port:port, service:"snmp", proto:"udp" );
  }
}

if( findhost_ports = get_kb_list( "synology/dsm/findhostd/port" ) ) {
  foreach port( findhost_ports ) {
    detection_methods += '\n\nfindhostd on port ' + port + "/udp";

    concluded = get_kb_item( "synology/dsm/findhostd/" + port + "/concluded" );
    if( concluded )
      detection_methods += '\n  Concluded from:' + concluded;

    register_product( cpe:hw_cpe, location:location, port:port, service:"findhostd", proto:"udp" );
    register_product( cpe:os_cpe, location:location, port:port, service:"findhostd", proto:"udp" );
    register_product( cpe:cpe, location:location, port:port, service:"findhostd", proto:"udp" );
  }
}

if( mdns_ports = get_kb_list( "synology/dsm/mdns/port" ) ) {
  foreach port( mdns_ports ) {
    concluded = get_kb_item( "synology/dsm/mdns/" + port + "/concluded" );

    if( concluded )
      detection_methods += '\n\n' + concluded;

    #nb: Although the service was discovered via mDNS, it actually resides on the TCP port exposed by mDNS
    if( ! registered ) { # nb: just making sure we only register once
      register_port = port;
      registered = TRUE;
    }
  }
}

if( upnp_ports = get_kb_list( "synology/dsm/upnp/port" ) ) {
  foreach port( upnp_ports ) {

    concluded = get_kb_item( "synology/dsm/upnp/" + port + "/concluded" );

    if( concluded ) {
      detection_methods += '\n\nUPnP on port ' + port + "/tcp";
      detection_methods += '\n  Concluded:' + concluded;
      upnp_loc = get_kb_item( "upnp/tcp/" + port + "/location" );
      if( upnp_loc )
        detection_methods += '\n  from URL:\n    ' + http_report_vuln_url( port:port, url:upnp_loc, url_only:TRUE );
    }

    if( ! registered ) { # nb: just making sure we only register once
      register_port = port;
      registered = TRUE;
    }
  }
}

if( registered ) {
  register_product( cpe:hw_cpe, location:location, port:register_port, service:"www" );
  register_product( cpe:os_cpe, location:location, port:register_port, service:"www" );
  register_product( cpe:cpe, location:location, port:register_port, service:"www" );
}

report  = build_detection_report( app:os_app,
                                  version:detected_version,
                                  install:location,
                                  cpe:os_cpe,
                                  extra:info );
report += '\n\n';
report += build_detection_report( app:hw_app,
                                  skip_version:TRUE,
                                  install:location,
                                  cpe:hw_cpe );
report += '\n\n';
report += build_detection_report( app:"Synology DiskStation Manager",
                                  skip_version:TRUE,
                                  install:location,
                                  cpe:cpe );

if( detection_methods )
  report += '\n\nDetection methods:' + detection_methods;

log_message( port:0, data:chomp( report ) );

exit( 0 );
