# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105068");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-08-19 11:37:55 +0200 (Tue, 19 Aug 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cyclades Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl", "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );

# Choose file to request based on what the remote host is supporting
if( http_can_host_asp( port:port ) && http_can_host_php( port:port ) ) {
  urls = make_list( "/home.asp", "/logon.php?redirect=index.php&nouser=1" );
} else if( http_can_host_asp( port:port ) ) {
  urls = make_list( "/home.asp" );
} else if( http_can_host_php( port:port ) ) {
  urls = make_list( "/logon.php?redirect=index.php&nouser=1" );
} else {
  exit( 0 );
}

foreach url( urls ) {

  buf = http_get_cache( item:url, port:port );

  if( "Welcome to the Cyclades" >!< buf ) continue;

  set_kb_item( name:"cyclades/installed", value:TRUE );
  CL = TRUE;
  install = url;

  if( 'class="is"' >< buf ) ts = TRUE;
  lines = split( buf, keep:FALSE );

  x = 0;
  f = 0;
  foreach line ( lines ) {
    x++;
    if( 'class="is"' >< line ) {
      f++;
      match = eregmatch( pattern:'<center>([^<]+)', string:line );
      if( ! isnull( match[1] ) ) info[f] = match[1];
    }

    else if( 'color="#003366"' >< line && ! ts ) {
      f++;
      match = eregmatch( pattern:'([^ <]+)', string:lines[x] );
      if( ! isnull( match[1] ) ) info[f] = match[1];
    }
  }
}

if( ! CL || ! info ) exit( 0 );

model = 'unknown';
vers  = 'unknown';

if( ! isnull( info[1] ) ) model = info[1];
if( ! isnull( info[2] ) ) host = info[2];
if( ! isnull( info[3] ) ) {
  version = eregmatch( pattern:'V_([^ ]+)', string: info[3] );
  if( ! isnull( version[1] ) ) vers = version[1];
}

set_kb_item( name:'cyclades/model', value:model );
set_kb_item( name:'cyclades/fw_version', value:vers );
set_kb_item( name:'cyclades/hostname', value:host );

cpe = 'cpe:/o:cyclades:' + tolower( model ) + ':' + tolower( vers );
os_register_and_report( os:"Cyclades " + model, cpe:cpe, banner_type:"HTTP banner", desc:"Cyclades Detection", runs_key:"unixoide" );

data = 'The remote host is a Cyclades-' + model + '.\nFirmware Version: ' + vers + '\n';
if( host ) data += 'Hostname: ' + host;

log_message( data:data, port:port );
exit( 0 );
