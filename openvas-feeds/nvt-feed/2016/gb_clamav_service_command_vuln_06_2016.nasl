# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105762");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-06-13 14:28:48 +0200 (Mon, 13 Jun 2016)");
  script_name("ClamAV 0.99.2 'SCAN' and 'SHUTDOWN' Command Injection Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_clamav_consolidation.nasl", "os_detection.nasl");
  script_require_ports("Services/clamd", 3310);
  script_mandatory_keys("clamav/remote/detected");

  script_xref(name:"URL", value:"https://blog.clamav.net/2016/06/regarding-use-of-clamav-daemons-tcp.html");
  script_xref(name:"URL", value:"https://bugzilla.clamav.net/show_bug.cgi?id=11585");
  script_xref(name:"URL", value:"https://blog.erratasec.com/2016/06/scanning-for-clamav-0day.html");

  script_tag(name:"summary", value:"ClamAV is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a SCAN command and checks the response.");

  script_tag(name:"insight", value:"ClamAV allows the execution of the clamav commands SCAN and
  SHUTDOWN without authentication.");

  script_tag(name:"affected", value:"ClamAV 0.99.2, and possibly other previous versions.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"clamd" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

vtstrings = get_vt_strings();

send( socket:soc, data:"SCAN /foo/bar/" + vtstrings["lowercase_rand"] + ".txt" );
recv = recv( socket:soc, length:1024 );
close( soc );

if( ! recv || "No such file or directory" >!< recv )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  send( socket:soc, data:"SCAN /" + file );
  recv = recv( socket:soc, length:1024 );

  if( "/" + file + ": OK" >< recv ) {
    report = 'It was possible to confirm the vulnerability by sending the "SCAN /' + file + '" clamav command. Response:\n\n' + recv;
    security_message( port:port, data:report );
    close(soc);
    exit( 0 );
  }
}

close(soc);
exit( 99 );
