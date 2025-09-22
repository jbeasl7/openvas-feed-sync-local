# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10330");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-01-14 10:12:23 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  # nb: Don't change this name as it will affect the script preferences of existing scan configs
  # as well as the predefined scan config which uses a fixed name for the preferences.
  script_name("Services");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("dont_scan_printers.nasl", "dont_print_on_printers.nasl",
                      "gb_dont_scan_fragile_device.nasl");

  # Keep these settings in sync with the nasl_builtin_find_service.c
  script_add_preference(name:"Number of connections done in parallel : ", value:"6", type:"entry", id:2);
  script_add_preference(name:"Network connection timeout : ", value:"20", type:"entry", id:3);
  script_add_preference(name:"Network read/write timeout : ", value:"20", type:"entry", id:4);
  script_add_preference(name:"Wrapped service read timeout : ", value:"20", type:"entry", id:5);

  script_add_preference(name:"SSL certificate : ", type:"file", value:"", id:6);
  script_add_preference(name:"SSL private key : ", type:"file", value:"", id:7);
  script_add_preference(name:"PEM password : ", type:"password", value:"", id:8);
  script_add_preference(name:"CA file : ", type:"file", value:"", id:9);
  script_add_preference(name:"Test SSL based services", type:"radio", value:"All;None", id:1); # nb: Don't change this name and id, these are hardcoded / used in GVMd

  script_timeout(4*360);

  script_tag(name:"summary", value:"This plugin performs service detection.");

  script_tag(name:"insight", value:"This plugin attempts to guess which service is running on the
  remote port(s). For instance, it searches for a web server which could listen on another port than
  80 or 443 and makes this information available for other check routines.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

# Run the built-in "nasl_builtin_find_service.c" of openvas-scanner
plugin_run_find_service();

if( ! COMMAND_LINE ) {

  # nb: Check for zebos_routing_shell and register it to avoid wrong service detection (dns, sip, yahoo messenger, ...)
  p = 2650;
  if( get_port_state( p ) ) {
    soc = open_sock_tcp( p );
    if( soc ) {
      recv = recv( socket:soc, length:128 );
      close( soc );
      if( "ZebOS" >< recv ) {
        service_register( port:p, proto:"zebos_routing_shell", message:"A ZebOS routing shell seems to be running on this port." );
        log_message( port:p, data:"A ZebOS routing shell seems to be running on this port." );
        exit( 0 );
      }
    }
  }

  # This service will be killed during later service detections so avoid this by checking it in here
  p = 27960;
  if( get_port_state( p ) ) {
    soc = open_sock_tcp( p );
    if( soc ) {
      recv = recv( socket:soc, length:128 );
      close( soc );
      if( egrep( pattern:"Welcome (.*). You have ([0-9]+) seconds to identify.", string:recv ) ) {
        service_register( port:p, proto:"enemyterritory", message:"An Enemy Territory Admin Mod seems to be running on this port." );
        log_message( port:p, data:"An Enemy Territory Admin Mod seems to be running on this port." );
        exit( 0 );
      }
    }
  }
}
