# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108731");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2020-03-24 13:59:25 +0000 (Tue, 24 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("rsync Service Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl");
  script_require_ports("Services/rsync", 873);

  script_xref(name:"URL", value:"https://rsync.samba.org");
  script_xref(name:"URL", value:"https://www.rfc-editor.org/rfc/rfc5781.html");

  script_tag(name:"summary", value:"TCP based detections of services supporting the rsync
  protocol.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("rsync_func.inc");
include("port_service_func.inc");

port = rsync_get_port( default:873 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

res = recv_line( socket:soc, length:1024 );
# nb: The same pattern is also checked in find_service1.nasl and find_service2.nasl. Please update those
# when updating the pattern here.
if( ! res || ( res !~ "^@RSYNCD: [0-9.]+" && res !~ "^You are not welcome to use rsync from " && res !~ "^rsync: (link_stat |error |.+unknown option)" &&
               res !~ "rsync error: (syntax or usage error|some files/attrs were not transferred) " && res !~ "rsync\s+version\s+.+\s+protocol version " ) ) {
  close( soc );
  exit( 0 );
}

set_kb_item( name:"rsync/detected", value:TRUE );
set_kb_item( name:"rsync/remote/detected", value:TRUE );
service_register( port:port, ipproto:"tcp", proto:"rsync", message:"A service supporting the rsync protocol is running at this port." );

protocol = eregmatch( string:res, pattern:"(^@RSYNCD:|\s+protocol version) ([0-9.]+)", icase:FALSE );
if( protocol[2] ) {
  report = "Detected RSYNCD protocol version: " + protocol[2];
  set_kb_item( name:"rsync/protocol_banner/" + port, value:protocol[0] );
  set_kb_item( name:"rsync/protocol_banner/available", value:TRUE );
}

if( res =~ "^You are not welcome to use rsync from " ) {
  if( report )
    report += '\n\n';
  report += "The rsync service is not allowing connections from this host.";
}

motd = "";

# Grab the MOTD
while( TRUE ) {
  buf = recv_line( socket:soc, length:8096 );
  if( ! buf || strstr( buf, '@ERROR' ) )
    break;
  motd += buf;
}

close( soc );

if( motd =~ "rsync: (link_stat |error |.+unknown option)" || "rsync error: " >< motd ||
    res =~ "rsync: (link_stat |error |.+unknown option)" || "rsync error: " >< res ) {
  motd_has_error = TRUE;
  if( report )
    report += '\n\n';
  if( "@RSYNCD:" >!< res )
    motd = res + motd;

  report += 'The rsync service is in a non-working state and reports the following error:\n\n' + chomp( motd );
}

if( motd && ! motd_has_error ) {
  motd = chomp( motd );
  if( report )
    report += '\n\n';
  report += 'Message of the Day reported by the service:\n\n' + motd;
  set_kb_item( name:"rsync/motd/" + port, value:motd );
  set_kb_item( name:"rsync/motd/available", value:TRUE );
}

# e.g.:
# rsync  version 3.1.1  protocol version 31
# rsync  version 3.0.7  protocol version 30
# nb: Those are rsync services in a "non" working state so we can't use that for version based checks.
# nb2: There are also different rsync service vendors so we're currently only registering the Samba CPE.
vers = eregmatch( string:res, pattern:"rsync\s+version ([0-9.]+)\s+protocol version [0-9.]+", icase:FALSE );
if( vers[1] && "samba.org" >< motd ) {
  cpe = "cpe:/a:samba:rsync:" + vers[1];
  install = port + "/tcp";
  register_product( cpe:cpe, location:install, port:port, service:"rsync" );
  report += '\n\n' + build_detection_report( app:"rsync", version:vers[1], install:install, cpe:cpe, concluded:vers[0] );
}

log_message( port:port, data:report );

exit( 0 );
