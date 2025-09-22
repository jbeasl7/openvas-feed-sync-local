# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103192");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-08-10 15:25:18 +0200 (Wed, 10 Aug 2011)");
  script_cve_id("CVE-2010-2132");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Adobe Flash Media Server Memory Corruption Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_adobe_fms_detect.nasl");
  script_mandatory_keys("Adobe/FMS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49103");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-20.html");

  script_tag(name:"solution", value:"The vendor has released an advisory and updates. Please see the
  references for details.");
  script_tag(name:"impact", value:"Successful exploits will allow attackers to crash the affected
  application, denying service to legitimate users. Due to the nature of
  this issue, arbitrary code execution may be possible. This has not been confirmed.");
  script_tag(name:"summary", value:"Adobe Flash Media Server is prone to a remote denial-of-service
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"4.0", test_version2:"4.0.2" ) ||
    version_is_less( version:vers, test_version:"3.5.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See vendor advisory" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
