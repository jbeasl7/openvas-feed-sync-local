# SPDX-FileCopyrightText: 2004 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15897");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-1999-0526");
  script_name("Open X Server");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2004 Michel Arboi");
  script_dependencies("X.nasl");
  script_require_ports("Services/X11", 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009);
  script_mandatory_keys("X11/open");

  script_tag(name:"summary", value:"An improperly configured X server will accept connections from clients from
  anywhere.");

  script_tag(name:"impact", value:"This allows an attacker to make a client connect to the X server to
  record the keystrokes of the user, which may contain sensitive information, such as account passwords.");

  script_tag(name:"solution", value:"Use xhost, MIT cookies, and filter incoming TCP connections to this port.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:6000, proto:"X11");
open = get_kb_item( "X11/" + port + "/open" );
if( ! open )
  exit( 0 );

security_message( port:port, data:"This X server accepts clients from anywhere. This allows an attacker to connect to it and record any of your keystrokes." );
exit( 0 );
