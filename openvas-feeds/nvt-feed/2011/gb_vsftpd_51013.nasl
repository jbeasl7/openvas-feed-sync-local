# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:beasts:vsftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103362");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-12-13 10:23:55 +0100 (Tue, 13 Dec 2011)");
  script_name("vsftpd '__tzfile_read()' Function Heap Based Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("sw_vsftpd_detect.nasl");
  script_mandatory_keys("vsftpd/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51013");
  script_xref(name:"URL", value:"http://dividead.wordpress.com/tag/heap-overflow/");
  script_xref(name:"URL", value:"https://security.appspot.com/vsftpd/Changelog.txt");
  script_xref(name:"URL", value:"https://security.appspot.com/vsftpd.html");

  script_tag(name:"summary", value:"vsftpd is prone to a buffer-overflow vulnerability because
  it fails to perform adequate boundary checks on user-supplied data.");

  script_tag(name:"impact", value:"Attackers may leverage this issue to execute arbitrary code in the
  context of the application. Failed attacks will cause denial-of-service conditions.");

  script_tag(name:"affected", value:"vsftpd 2.3.4 is affected. Other versions may also be vulnerable.");

  script_tag(name:"solution", value:"A fixed version 2.3.5 is available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"2.3.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.3.5" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
