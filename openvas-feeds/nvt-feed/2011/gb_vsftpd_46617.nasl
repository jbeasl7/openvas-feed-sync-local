# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:beasts:vsftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103101");
  script_version("2024-03-01T14:37:10+0000");
  script_cve_id("CVE-2011-0762");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-03-03 13:33:12 +0100 (Thu, 03 Mar 2011)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("vsftpd FTP Server 'ls.c' Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("sw_vsftpd_detect.nasl");
  script_mandatory_keys("vsftpd/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46617");
  script_xref(name:"URL", value:"https://security.appspot.com/vsftpd/Changelog.txt");
  script_xref(name:"URL", value:"https://security.appspot.com/vsftpd.html");

  script_tag(name:"solution", value:"A fixed version 2.3.3 is available. Please see the references for more information.");

  script_tag(name:"summary", value:"The 'vsftpd' FTP server is prone to a remote denial-of-service
  vulnerability.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows remote attackers to crash
  the affected application, denying service to legitimate users.");

  script_tag(name:"affected", value:"vsftpd versions 2.3.2 and below are vulnerable.");

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

if( version_in_range( version:vers, test_version:"2.0", test_version2:"2.3.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.3.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
