# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813383");
  script_version("2024-02-22T14:37:29+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-22 14:37:29 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-06-04 12:52:08 +0530 (Mon, 04 Jun 2018)");
  script_name("Bitvise SSH Server Detection (SSH Banner)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/bitvise/ssh_server/detected");

  script_tag(name:"summary", value:"SSH banner-based detection of Bitvise SSH Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

if( ! banner = ssh_get_serverbanner( port:port ) )
  exit( 0 );

# SSH-2.0-5.23 FlowSsh: Bitvise SSH Server (WinSSHD) 6.04
# SSH-2.0-5.17 FlowSsh: Bitvise SSH Server (WinSSHD) 5.60: free only for personal non-commercial use
# SSH-2.0-8.49 FlowSsh: Bitvise SSH Server (WinSSHD) 8.49
# SSH-2.0-9.32 FlowSsh: Bitvise SSH Server (WinSSHD) 9.32: free only for personal non-commercial use
# SSH-2.0-9.99 FlowSsh: Bitvise SSH Server (WinSSHD)
#
# nb: Keep the pattern "in sync" with ssh_detect.nasl and gb_ssh_os_detection.nasl
if( banner =~ "SSH.*Bitvise SSH Server \(WinSSHD\)" ) {

  version = "unknown";

  set_kb_item( name:"bitvise/ssh_server/detected", value:TRUE );
  set_kb_item( name:"bitvise/ssh_server/ssh-banner/detected", value:TRUE );
  set_kb_item( name:"bitvise/ssh_server/ssh-banner/port", value:port );
  set_kb_item( name:"bitvise/ssh_server/ssh-banner/" + port + "/concluded", value:banner );

  vers = eregmatch( pattern:"Bitvise SSH Server \(WinSSHD\) ([0-9.]+)", string:banner );
  if( vers[1] )
    version = vers[1];

  set_kb_item( name:"bitvise/ssh_server/ssh-banner/" + port + "/version", value:version );
}

exit( 0 );
