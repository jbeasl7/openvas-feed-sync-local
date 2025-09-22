# SPDX-FileCopyrightText: 2005 Alert4Web.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10758");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("VNC Viewer Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Alert4Web.com");
  script_family("Service detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 5800);
  script_mandatory_keys("vncviewer_jc/banner");

  script_tag(name:"summary", value:"HTTP based detection of a VNC viewer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:5800 );

banner = http_get_remote_headers( port:port );
if( ! banner )
  exit( 0 );

if( "vncviewer.jar" >< banner || "vncviewer.class" >< banner ) {
  log_message( port:port );
  set_kb_item( name:"www/vnc", value:TRUE );
}

exit( 99 );
