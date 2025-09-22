# SPDX-FileCopyrightText: 2001 Noam Rathaus
# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10744");
  script_version("2023-09-06T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-06 05:05:19 +0000 (Wed, 06 Sep 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("VisualRoute Web Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 SecuriTeam & Copyright (C) 2001 Noam Rathaus");
  script_family("General");
  script_dependencies("gb_visualroute_detect.nasl");
  script_mandatory_keys("visualroute/detected");

  script_tag(name:"solution", value:"Disable the VisualRoute web server, or block the web server's
  port number on your Firewall.");

  script_tag(name:"summary", value:"We detected the remote web server as being a VisualRoute web server.
  This server allows attackers to perform a traceroute to a third party's
  hosts without revealing themselves to the target of the traceroute.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

CPE = "cpe:/a:visualware:visualroute";

include( "host_details.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! location = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

report = "The target is exposing a VisualRoute web server on port " + location;
security_message( data: report, port: port );
exit( 0 );
