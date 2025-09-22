# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100754");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-08-11 13:11:12 +0200 (Wed, 11 Aug 2010)");
  script_cve_id("CVE-2010-2218", "CVE-2010-2217", "CVE-2010-2219", "CVE-2010-2220");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Media Server Multiple Remote Security Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_adobe_fms_detect.nasl");
  script_mandatory_keys("Adobe/FMS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42344");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-19.html");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code in the
  context of the affected application or cause denial-of-service conditions.");
  script_tag(name:"affected", value:"These issues affect Flash Media Server (FMS) versions prior to 3.5.4
  and 3.0.6.");
  script_tag(name:"solution", value:"Vendor updates are available. Please see the referenced advisory for
  more information.");
  script_tag(name:"summary", value:"Adobe Flash Media Server is prone to multiple remote security
  vulnerabilities, including multiple denial-of-service vulnerabilities
  and a remote code execution (RCE) vulnerability.");

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

if( version_in_range( version:vers, test_version:"3.5", test_version2:"3.5.3" ) ||
    version_is_less( version:vers, test_version:"3.0.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.6/3.5.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
