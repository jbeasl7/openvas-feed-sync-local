# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:beasts:vsftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108045");
  script_cve_id("CVE-2015-1419");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-01-18 10:23:55 +0100 (Wed, 18 Jan 2017)");
  script_name("vsftpd < 3.0.3 Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("sw_vsftpd_detect.nasl");
  script_mandatory_keys("vsftpd/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72451");
  script_xref(name:"URL", value:"https://security.appspot.com/vsftpd/Changelog.txt");

  script_tag(name:"summary", value:"vsftpd is prone to a security bypass vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass certain
  security restrictions and perform unauthorized actions. This may aid in further attacks.");

  script_tag(name:"affected", value:"vsftpd versions 3.0.2 and below are vulnerable.");

  script_tag(name:"solution", value:"A fixed version 3.0.3 is available. Please see the references for more information.");

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

if( version_is_less( version:vers, test_version:"3.0.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
