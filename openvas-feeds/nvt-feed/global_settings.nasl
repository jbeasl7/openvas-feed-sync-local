# SPDX-FileCopyrightText: 2005 Michel Arboi
# SPDX-FileCopyrightText: New code / functionality since 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12288");
  script_version("2025-09-01T05:39:44+0000");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Global variable settings"); # nb: Don't change the script name, this name is hardcoded within some manager functions...
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Settings");

  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc1918");

  script_add_preference(name:"Enable CGI scanning", type:"checkbox", value:"yes", id:2);
  script_add_preference(name:"Add historic /scripts and /cgi-bin to directories for CGI scanning", type:"checkbox", value:"no", id:3);
  script_add_preference(name:"Regex pattern to exclude directories from CGI scanning : ", type:"entry", value:"/(index\.php|image|img|css|js$|js/|javascript|style|theme|icon|jquery|graphic|grafik|picture|bilder|thumbnail|media/|skins?/)", id:4);
  script_add_preference(name:"Use regex pattern to exclude directories from CGI scanning : ", type:"checkbox", value:"yes", id:5);
  script_add_preference(name:"Exclude directories containing detected known server manuals from CGI scanning", type:"checkbox", value:"yes", id:6);
  script_add_preference(name:"Enable generic web application scanning", type:"checkbox", value:"no", id:7);
  script_add_preference(name:"Disable caching of web pages during CGI scanning", type:"checkbox", value:"no", id:18);
  script_add_preference(name:"Traversal depth to use for directory traversal attacks during CGI scanning", type:"entry", value:"6", id:19);
  script_add_preference(name:"Include OID in the User Agent within HTTP requests of various VTs for debugging purposes", type:"checkbox", value:"no", id:21);

  script_add_preference(name:"Network type", type:"radio", value:"Mixed (use RFC 1918);Private LAN;Public WAN (Internet);Public LAN", id:8);
  script_add_preference(name:"Report verbosity", type:"radio", value:"Normal;Quiet;Verbose", id:9);

  script_add_preference(name:"Log verbosity", type:"radio", value:"Normal;Quiet;Verbose;Debug", id:10);
  script_add_preference(name:"Debug level", type:"entry", value:"0", id:11);
  script_add_preference(name:"HTTP User-Agent", type:"entry", value:"", id:12);

  # nb: Don't change this name and id, these are hardcoded / used in GVMd
  script_add_preference(name:"Strictly unauthenticated", type:"checkbox", value:"no", id:1);

  script_add_preference(name:"Exclude printers from scan", type:"checkbox", value:"yes", id:13);
  script_add_preference(name:"Exclude known fragile devices/ports from scan", type:"checkbox", value:"yes", id:14);
  script_add_preference(name:"Enable SSH Debug", type:"checkbox", value:"no", id:15);

  # nb: Kept here on purpose so that we can warn about the usage of a deprecated function via the
  # log_message() below.
  script_add_preference(name:"Mark host as dead if going offline (failed ICMP ping) during scan (deprecated)", type:"checkbox", value:"no", id:16);

  script_add_preference(name:"Service discovery on non-default UDP ports (slow)", type:"checkbox", value:"no", id:17);
  script_add_preference(name:"External out-of-band server", type:"entry", value:"oast.live", id:20);

  script_tag(name:"summary", value:"This plugin configures miscellaneous global variables for NASL
  scripts.

  It does not perform any security check but may disable or change the behaviour of others.");

  script_tag(name:"insight", value:"- External out-of-band server:

  Used for out-of-band (OOB) interactions in specific active checks where an external systems is
  required. Currently this system needs to be accessible to the target via HTTP(s) and respond to
  all HTTP requests (including e.g. POST methods) with a 200 (Found) HTTP status code.

  - Network type:

  This allows to configure the type of the network which is getting scanned to change the behaviour
  / results of some Vulnerability Tests. If the scanned network is e.g. a private LAN which contains
  systems not accessible to the public (access restricted) and it is accepted that some of these
  systems are accessible without a password set this setting to 'Private LAN'.

  Note: The 'Mark host as dead if going offline (failed ICMP ping) during scan (deprecated)'
  functionality is deprecated and therefore no longer functional. Please:

  - Update the software on the scanner host to version 22.04 or later

  - Configure the system to use Boreas (already configured if using the Greenbone Operating System
  22.04+)

  - Use / configure the 'max_vts_timeouts' scanner preference accordingly");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("network_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("plugin_feed_info.inc");

opt = script_get_preference( "Service discovery on non-default UDP ports (slow)", id:17 );
if( opt == "yes" )
  set_kb_item( name:"global_settings/non-default_udp_service_discovery", value:TRUE );

opt = script_get_preference( "Mark host as dead if going offline (failed ICMP ping) during scan (deprecated)", id:16 );
if( opt == "yes" ) {
  report  = "IMPORTANT: The 'Mark host as dead if going offline (failed ICMP ping) during scan (deprecated)' setting is deprecated and the relevant functionality has been removed. Please:";
  report += '\n - Update the software on the scanner host to version 22.04 or later';
  report += '\n - Configure the system to use Boreas (already configured if using the Greenbone Operating System 22.04+)';
  report += '\n - Use / configure the "max_vts_timeouts" scanner preference accordingly';
  log_message( port:0, data:report );
}

opt = script_get_preference( "Enable CGI scanning", id:2 );
if( opt == "no" )
  set_kb_item( name:"Settings/disable_cgi_scanning", value:TRUE );

opt = script_get_preference( "Exclude directories containing detected known server manuals from CGI scanning", id:6 );
if( ! opt || opt == "yes" )
  set_kb_item( name:"global_settings/cgi_dirs_exclude_servermanual", value:TRUE );

opt = script_get_preference( "Enable generic web application scanning", id:7 );
if( opt == "no" )
  set_kb_item( name:"global_settings/disable_generic_webapp_scanning", value:TRUE );

opt = script_get_preference( "Disable caching of web pages during CGI scanning", id:18 );
if( opt && opt == "yes" )
  set_kb_item( name:"global_settings/disable_http_kb_caching", value:TRUE );

opt = script_get_preference( "Traversal depth to use for directory traversal attacks during CGI scanning", id:19 );
if( opt && opt =~ "^[1-9][0-9]*$" )
  depth = opt;
else
  depth = "6"; # nb: traversal_pattern() in misc_func.inc currently has the default depth of 6 as well.
set_kb_item( name:"global_settings/dir_traversal_depth", value:depth );

opt = script_get_preference( "Regex pattern to exclude directories from CGI scanning : ", id:4 );
if( ! opt )
  set_kb_item( name:"global_settings/cgi_dirs_exclude_pattern", value:"/(index\.php|image|img|css|js$|js/|javascript|style|theme|icon|jquery|graphic|grafik|picture|bilder|thumbnail|media/|skins?/)" );
else
  set_kb_item( name:"global_settings/cgi_dirs_exclude_pattern", value:opt );

opt = script_get_preference( "Use regex pattern to exclude directories from CGI scanning : ", id:5 );
if( opt != "no" )
  set_kb_item( name:"global_settings/use_cgi_dirs_exclude_pattern", value:TRUE );

opt = script_get_preference( "Report verbosity", id:9 );
if( ! opt )
  opt = "Normal";
set_kb_item( name:"global_settings/report_verbosity", value:opt );

opt = script_get_preference( "Log verbosity", id:10 );
if( ! opt )
  opt = "Quiet";
set_kb_item( name:"global_settings/log_verbosity", value:opt );

opt = script_get_preference( "Debug level", id:11 );
if( ! opt )
  opt = "0";
set_kb_item( name:"global_settings/debug_level", value:int( opt ) );

opt = script_get_preference( "Network type", id:8 );
if( ! opt )
  opt = "Mixed (RFC 1918)";
set_kb_item( name:"global_settings/network_type", value:opt );

opt = script_get_preference( "HTTP User-Agent", id:12 );
if( ! opt ) {
  vt_strings = get_vt_strings();
  opt = http_get_user_agent( vt_string:vt_strings["default_dash"], dont_add_oid:TRUE );
}
set_kb_item( name:"global_settings/http_user_agent", value:opt );
set_kb_item( name:"http/user-agent", value:opt );

opt = script_get_preference( "Strictly unauthenticated", id:1 );
if( opt == "yes" )
  set_kb_item( name:"global_settings/authenticated_scans_disabled", value:TRUE );

opt = script_get_preference( "Exclude printers from scan", id:13 );
if( opt == "yes" )
  set_kb_item( name:"global_settings/exclude_printers", value:"yes" );

opt = script_get_preference( "Exclude known fragile devices/ports from scan", id:14 );
if( opt == "yes" )
  set_kb_item( name:"global_settings/exclude_fragile", value:TRUE );

cgi_bin = cgibin();
if( cgi_bin ) {
  cgis = split( cgi_bin, sep:":", keep:FALSE );
  opt  = script_get_preference( "Add historic /scripts and /cgi-bin to directories for CGI scanning", id:3 );

  foreach cgi( cgis ) {
    if( ( cgi == "/scripts" || cgi == "/cgi-bin" ) && ( ! opt || opt == "no" ) )
      exclude_cgis = TRUE;
    else
      set_kb_item( name:"/user/cgis", value:cgi );
  }

  if( exclude_cgis )
    set_kb_item( name:"global_settings/exclude_historic_cgi_dirs", value:TRUE );
}

opt = script_get_preference( "Enable SSH Debug", id:15 );
if( opt == "yes" )
  set_kb_item( name:"global_settings/ssh/debug", value:TRUE );

if( TARGET_IS_IPV6() )
  set_kb_item( name:"keys/TARGET_IS_IPV6", value:TRUE );

if( islocalhost() )
  set_kb_item( name:"keys/islocalhost", value:TRUE );

if( islocalnet() )
  set_kb_item( name:"keys/islocalnet", value:TRUE );

if( is_private_addr() )
  set_kb_item( name:"keys/is_private_addr", value:TRUE );

if( is_public_addr() )
  set_kb_item( name:"keys/is_public_addr", value:TRUE );

if( is_private_lan() )
  set_kb_item( name:"keys/is_private_lan", value:TRUE );

opt = script_get_preference( "External out-of-band server", id:20 );
if( opt )
  set_kb_item( name:"global_settings/out-of-band_server", value:opt );

opt = script_get_preference( "Include OID in the User Agent within HTTP requests of various VTs for debugging purposes", id:21 );
if( opt && opt == "yes" )
  set_kb_item( name:"global_settings/http_ua_include_oid", value:TRUE );

# nb: We have seen some race conditions if a feed update was done during scans where this constant
# was empty. This was probably because the plugin_feed_info.inc file just got overwritten by the
# sync process at the time the info was read from it. As this constant should be always there and we
# don't have any control over the feed sync process we're just sleeping for a second and try again
# afterwards as some kind of workaround until the feed sync process was made more resilient.
if( ! FEED_NAME )
  sleep( 1 );

# nb:
# - Mainly used in / for gb_outdated_scan_engine.nasl
# - The info about the content of this constant is getting added as a host detail (to e.g. reports)
#   separately in / via host_scan_end.nasl
if( FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM" )
  set_kb_item( name:"keys/is_gef", value:TRUE );

else if( FEED_NAME == "GCF" )
  set_kb_item( name:"keys/is_gcf", value:TRUE );

else
  set_kb_item( name:"keys/is_unknown_feed", value:TRUE );

exit( 0 );
