# SPDX-FileCopyrightText: 2000 Julio César Hernández
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10316");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WinSATAN Backdoor Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2000 Julio César Hernández");
  script_family("Malware");
  script_dependencies("find_service.nasl");
  script_require_ports(999);

  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/75/17508");
  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/75/17663");

  script_tag(name:"impact", value:"An attacker may use it to steal your password or prevent
  your system from working properly.");

  script_tag(name:"solution", value:"Use RegEdit, and find 'RegisterServiceBackUp'
  in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

  The value's data is the path of the file.
  If you are infected by WinSATAN, then
  the registry value is named 'fs-backup.exe'.");

  script_tag(name:"summary", value:"WinSATAN is installed.

  This backdoor allows anyone to partially take control
  of the remote system.");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include('ftp_func.inc');

port = 999;
if( ! get_port_state( port ) ) exit( 0 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

if( ftp_authenticate( socket:soc, user:"uyhw6377w", pass:"bhw32qw" ) ) {
  security_message( port:port );
  close( soc );
  exit( 0 );
}

close( soc );
exit( 99 );