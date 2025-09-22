# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114697");
  script_version("2024-07-12T15:38:44+0000");
  script_tag(name:"last_modification", value:"2024-07-12 15:38:44 +0000 (Fri, 12 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-10 11:38:18 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dell DRAC / iDRAC Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_dell_drac_idrac_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_dell_drac_idrac_ssh_login_detect.nasl");
  script_mandatory_keys("dell/idrac/detected");

  script_xref(name:"URL", value:"https://www.dell.com/en-us/lp/dt/open-manage-idrac");

  script_tag(name:"summary", value:"Consolidation of Dell Remote Access Controller (DRAC) /
  Integrated Remote Access Controller (iDRAC) detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if( ! get_kb_item( "dell/idrac/detected" ) )
  exit( 0 );

detected_fw_version = "unknown";
detected_fw_build = "unknown";
detected_idrac_generation = "unknown";
detected_server_generation = "unknown";

foreach source( make_list( "http", "ssh-login" ) ) {
  fw_version_list = get_kb_list( "dell/idrac/" + source + "/*/fw_version" );
  foreach fw_version( fw_version_list ) {
    if( fw_version != "unknown" && detected_fw_version == "unknown" ) {
      detected_fw_version = fw_version;
      set_kb_item( name:"dell/idrac/fw_version", value:detected_fw_version );
      break;
    }
  }

  # nb: The iDRAC Generation (e.g. 5, 6, 7, 8 or 9) is not directly exposed in most cases so we're
  # using the Server generation (e.g. 12G, 13G, 14G or 15G) and determine the iDRAC generation from
  # it first.
  server_generation_list = get_kb_list( "dell/idrac/" + source + "/*/server_generation" );
  foreach server_generation( server_generation_list ) {
    if( server_generation != "unknown" && detected_server_generation == "unknown" ) {
      detected_server_generation = server_generation;
      set_kb_item( name:"dell/idrac/server_generation", value:detected_server_generation );

      if( detected_server_generation == "10G" ||
          detected_server_generation == "11G" ) {
        detected_idrac_generation = "6";
      } else if( detected_server_generation == "12G" ) {
        detected_idrac_generation = "7";
      } else if( detected_server_generation == "13G" ) {
        detected_idrac_generation = "8";
      } else if( detected_server_generation == "14G" ||
                 detected_server_generation == "15G" ||
                 detected_server_generation == "16G" ) {
        detected_idrac_generation = "9";
      }

      if( detected_idrac_generation != "unknown" )
        set_kb_item( name:"dell/idrac/idrac_generation", value:detected_idrac_generation );

      break;
    }
  }

  # nb: Only as a fallback, the iDRAC generation might have been already detected previously
  idrac_generation_list = get_kb_list( "dell/idrac/" + source + "/*/idrac_generation" );
  foreach idrac_generation( idrac_generation_list ) {
    if( idrac_generation != "unknown" && detected_idrac_generation == "unknown" ) {
      detected_idrac_generation = idrac_generation;
      set_kb_item( name:"dell/idrac/idrac_generation", value:detected_idrac_generation );
      break;
    }
  }

  fw_build_list = get_kb_list( "dell/idrac/" + source + "/*/fw_build" );
  foreach fw_build( fw_build_list ) {
    if( fw_build != "unknown" && detected_fw_build == "unknown" ) {
      detected_fw_build = fw_build;
      set_kb_item( name:"dell/idrac/fw_build", value:detected_fw_build );
      extra_build_info = "  Firmware build: " + fw_build;
      break;
    }
  }
}

if( detected_idrac_generation != "unknown" ) {
  base_cpe = "cpe:/a:dell:idrac" + detected_idrac_generation;
  app_name = "Dell DRAC / iDRAC " + detected_idrac_generation;
} else {
  base_cpe = "cpe:/a:dell:idrac";
  app_name = "Dell DRAC / iDRAC";
}

cpe = build_cpe( value:detected_fw_version, exp:"^([0-9.]+)", base:base_cpe + ":" );
if( ! cpe )
  cpe = base_cpe;

location = "/";

if( http_ports = get_kb_list( "dell/idrac/http/port" ) ) {
  foreach port( http_ports ) {
    extra += "- HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item( "dell/idrac/http/" + port + "/concluded" );
    if( concluded )
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    concUrl = get_kb_item( "dell/idrac/http/" + port + "/concUrl" );
    if( concUrl )
      extra += '  Concluded from version/product identification location:\n' + concUrl + '\n';

    register_product( cpe:cpe, location:location, port:port, service:"www" );
  }
}

if( ssh_login_ports = get_kb_list( "dell/idrac/ssh-login/port" ) ) {
  foreach port( ssh_login_ports ) {
    extra += "- SSH login on port " + port + '/tcp\n';

    concluded = get_kb_item( "dell/idrac/ssh-login/" + port + "/concluded" );
    if( concluded )
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product( cpe:cpe, location:location, port:port, service:"ssh-login" );
  }
}

report = build_detection_report( app:app_name, version:detected_fw_version, install:location, cpe:cpe, extra:extra_build_info );

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message( port:0, data:chomp( report ) );

exit( 0 );
