# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104593");
  script_version("2026-04-28T06:28:06+0000");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2023-03-07 07:51:46 +0000 (Tue, 07 Mar 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Riello UPS / NetMan Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_riello_ups_netman_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_riello_ups_netman_ftp_detect.nasl",
                        "gsf/gb_riello_ups_netman_snmp_detect.nasl");
  script_mandatory_keys("riello/netman/detected");

  script_tag(name:"summary", value:"Consolidation of Riello NetMan network card and the
  underlying uninterruptible power supply (UPS) device detections.");

  script_xref(name:"URL", value:"https://www.riello-ups.com/");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item( "riello/netman/detected" ) )
  exit( 0 );

detected_ups_model = "unknown";
detected_ups_fw_version = "unknown";
detected_netman_card = "unknown";
detected_netman_app_version = "unknown";
detected_netman_sys_version = "unknown";

foreach source( make_list( "http", "snmp" ) ) {
  ups_model_list = get_kb_list( "riello/netman/" + source + "/*/ups_model" );
  foreach ups_model( ups_model_list ) {
    if( ups_model != "unknown" && detected_ups_model == "unknown" ) {
      detected_ups_model = ups_model;
      set_kb_item( name:"riello/ups/model", value:detected_ups_model );
      break;
    }
  }

  ups_fw_vers_list = get_kb_list( "riello/netman/" + source + "/*/ups_fw_version" );
  foreach ups_fw_vers( ups_fw_vers_list ) {
    if( ups_fw_vers != "unknown" && detected_ups_fw_version == "unknown" ) {
      detected_ups_fw_version = ups_fw_vers;
      set_kb_item( name:"riello/ups/firmware_version", value:detected_ups_fw_version );
      break;
    }
  }

  netman_card_list = get_kb_list( "riello/netman/" + source + "/*/netman_card" );
  foreach netman_card( netman_card_list ) {
    if( netman_card != "unknown" && detected_netman_card == "unknown" ) {
      detected_netman_card = netman_card;
      set_kb_item( name:"riello/netman/netman_card", value:detected_netman_card );
      break;
    }
  }

  netman_sys_vers_list = get_kb_list( "riello/netman/" + source + "/*/netman_sys_version" );
  foreach netman_sys_vers( netman_sys_vers_list ) {
    if( netman_sys_vers != "unknown" && detected_netman_sys_version == "unknown" ) {
      detected_netman_sys_version = netman_sys_vers;
      set_kb_item( name:"riello/netman/sys_version", value:detected_netman_sys_version );
      break;
    }
  }

  netman_app_vers_list = get_kb_list( "riello/netman/" + source + "/*/netman_app_version" );
  foreach netman_app_vers( netman_app_vers_list ) {
    if( netman_app_vers != "unknown" && detected_netman_app_version == "unknown" ) {
      detected_netman_app_version = netman_app_vers;
      set_kb_item( name:"riello/netman/app_version", value:detected_netman_app_version );
      break;
    }
  }
}

if( detected_netman_card != "unknown" ) {
  netman_hw_name = "Riello NetMan " + detected_netman_card;
  netman_hw_cpe = "cpe:/h:riello-ups:netman_" + detected_netman_card;
} else {
  netman_hw_name = "Riello NetMan";
  netman_hw_cpe = "cpe:/h:riello-ups:netman";
}

if( detected_ups_model != "unknown" ) {
  ups_hw_name = "Riello " + detected_ups_model + " UPS";
  ups_hw_cpe = "cpe:/h:riello-ups:" + tolower( detected_ups_model );
  # nb: Some models (at least via SNMP) are gathered with a space in between like e.g.:
  # MST 30
  ups_hw_cpe = str_replace( string:ups_hw_cpe, find:" ", replace:"_" );
} else {
  ups_hw_name = "Riello Unknown UPS Model";
  ups_hw_cpe = "cpe:/h:riello-ups:unknown_model";
}

# The "firmware" version of the UPS is added to the hardware CPE of it
if( detected_ups_fw_version != "unknown" )
  ups_hw_cpe += ":" + tolower( detected_ups_fw_version );

if( detected_netman_card != "unknown" ) {
  netman_os_name = "Riello NetMan " + detected_netman_card + " Firmware";
  netman_os_cpe = "cpe:/o:riello-ups:netman_" + detected_netman_card + "_firmware";
} else {
  netman_os_name = "Riello NetMan Firmware";
  netman_os_cpe = "cpe:/o:riello-ups:netman_firmware";
}

# nb: We're assuming the System version as the OS version for now until otherwise determined that
# the Application version should be used instead
if( detected_netman_sys_version != "unknown" )
  netman_os_cpe += ":" + tolower( detected_netman_sys_version );

# nb: "Application version" might be the version of the web app
if( detected_netman_card != "unknown" ) {
  netman_app_name = "Riello NetMan " + detected_netman_card + " Application";
  netman_app_cpe = "cpe:/a:riello-ups:netman_" + detected_netman_card;
} else {
  netman_app_name = "Riello NetMan Application";
  netman_app_cpe = "cpe:/a:riello-ups:netman";
}

if( detected_netman_app_version != "unknown" )
  netman_app_cpe += ":" + tolower( detected_netman_app_version );

os_register_and_report( os:netman_os_name, cpe:netman_os_cpe, port:0, runs_key:"unixoide",
                        desc:"Riello UPS / NetMan Detection Consolidation" );

install = "/";

if( http_ports = get_kb_list( "riello/netman/http/port" ) ) {
  foreach port( http_ports ) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item( "riello/netman/http/" + port + "/concluded" );
    if( concluded )
      extra += "  Concluded from version/product identification result:" + concluded + '\n';

    concUrl = get_kb_item( "riello/netman/http/" + port + "/concludedUrl" );
    if( concUrl )
      extra += '  Concluded from version/product identification location:\n' + concUrl + '\n';

    register_product( cpe:netman_os_cpe, location:install, port:port, service:"www" );
    register_product( cpe:netman_hw_cpe, location:install, port:port, service:"www" );
    register_product( cpe:ups_hw_cpe, location:install, port:port, service:"www" );
    register_product( cpe:netman_app_cpe, location:install, port:port, service:"www" );
  }
}

if( ftp_ports = get_kb_list( "riello/netman/ftp/port" ) ) {
  foreach port( ftp_ports ) {
    extra += "FTP on port " + port + '/tcp\n';

    concluded = get_kb_item( "riello/netman/ftp/" + port + "/concluded" );
    if( concluded )
      extra += "  Concluded from version/product identification result:" + concluded + '\n';

    register_product( cpe:netman_os_cpe, location:install, port:port, service:"ftp" );
    register_product( cpe:netman_hw_cpe, location:install, port:port, service:"ftp" );
    register_product( cpe:ups_hw_cpe, location:install, port:port, service:"ftp" );
    register_product( cpe:netman_app_cpe, location:install, port:port, service:"ftp" );
  }
}

if( snmp_ports = get_kb_list( "riello/netman/snmp/port" ) ) {
  foreach port( snmp_ports ) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item( "riello/netman/snmp/" + port + "/concluded" );
    if( concluded )
      extra += "  Concluded from version/product identification result:" + concluded + '\n';

    register_product( cpe:netman_os_cpe, location:install, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:netman_hw_cpe, location:install, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:ups_hw_cpe, location:install, port:port, service:"snmp", proto:"udp" );
    register_product( cpe:netman_app_cpe, location:install, port:port, service:"snmp", proto:"udp" );
  }
}

report = build_detection_report( app:netman_os_name, version:detected_netman_sys_version, install:install, cpe:netman_os_cpe );
report += '\n\n';
report += build_detection_report( app:netman_hw_name, skip_version:TRUE, install:install, cpe:netman_hw_cpe );
report += '\n\n';
report += build_detection_report( app:ups_hw_name, version:detected_ups_fw_version, install:install, cpe:ups_hw_cpe );
report += '\n\n';
report += build_detection_report( app:netman_app_name, version:detected_netman_app_version, install:install, cpe:netman_app_cpe );

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message( port:0, data:chomp( report ) );

exit( 0 );
