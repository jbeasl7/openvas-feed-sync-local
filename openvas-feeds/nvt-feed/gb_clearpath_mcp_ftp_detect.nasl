# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140188");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-03-14 17:59:06 +0100 (Tue, 14 Mar 2017)");
  script_name("ClearPath MCP Detection (FTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/clearpath/mcp/detected");

  script_tag(name:"summary", value:"The script sends a connection request to the server
  and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = ftp_get_port( default:21 );
if( ! banner = ftp_get_banner( port:port ) ) exit( 0 );
if( "FTP Services for ClearPath MCP" >!< banner ) exit( 0 );

set_kb_item( name:"unisys/clearpath_mcp/installed", value:TRUE );

cpe = 'cpe:/a:unisys:clearpath_mcp';
version = 'unknown';

v = eregmatch( pattern:'Server version ([0-9.]+)', string:banner );

if( ! isnull( v[1] ) ) {
  version = v[1];
  set_kb_item( name:"unisys/clearpath_mcp/version", value:version );
  cpe += ':' + version;
}

register_product( cpe:cpe, location:port + '/tcp', port:port, service:"ftp" );

report = build_detection_report( app:"ClearPath MCP", version:version, install:port + '/tcp', cpe:cpe, concluded:banner );

log_message( port:port, data:report );

exit( 0 );
