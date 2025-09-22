# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103585");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-11 15:52:11 +0100 (Thu, 11 Oct 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Nmap MAC Scan");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("toolcheck.nasl", "host_alive_detection.nasl", "global_settings.nasl");
  script_family("Service detection");
  script_mandatory_keys("Tools/Present/nmap", "keys/islocalnet");

  script_tag(name:"summary", value:"This script attempts to gather the MAC address of the target.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

if( ! islocalnet() ) exit( 0 );

argv[x++] = "nmap";
argv[x++] = "-sP";

ip = get_host_ip();

if( TARGET_IS_IPV6() )
  argv[x++] = "-6";

# Apply the chosen nmap timing policy from nmap.nasl here as well
timing_policy = get_kb_item( "Tools/nmap/timing_policy" );
if( timing_policy =~ "^-T[0-5]$" )
  argv[x++] = timing_policy;

source_iface = get_preference( "source_iface" );
if( source_iface =~ "^[0-9a-zA-Z:_]+$" ) {
  argv[x++] = "-e";
  argv[x++] = source_iface;
}

argv[x++] = ip;

res = pread( cmd:"nmap", argv:argv );
if( isnull( res ) || "MAC" >!< res ) exit( 0 );

mac = eregmatch( pattern:"MAC Address: ([0-9a-fA-F:]{17})", string:res );

if( ! isnull( mac[1] ) ) {
  register_host_detail( name:"MAC", value:mac[1], desc:"Nmap MAC Scan" );
  replace_kb_item( name:"Host/mac_address", value:mac[1] );
}

exit( 0 );