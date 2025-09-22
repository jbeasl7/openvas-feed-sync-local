# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800183");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-11-19 15:31:49 +0100 (Fri, 19 Nov 2010)");
  script_cve_id("CVE-2010-3633", "CVE-2010-3634", "CVE-2010-3635");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Media Server Multiple Denial of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_fms_detect.nasl");
  script_mandatory_keys("Adobe/FMS/installed");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-27.html");

  script_tag(name:"impact", value:"Successful exploitation will let the remote unauthenticated attackers to
  run malicious code and crash the application resulting denial of service.");

  script_tag(name:"affected", value:"Flash Media Server 3.0.x before 3.0.7, 3.5.x before 3.5.5
  and 4.0.x before 4.0.1.");

  script_tag(name:"insight", value:"The flaws are due to unspecified vectors. Please see the references for
  more details.");

  script_tag(name:"solution", value:"Update to 4.0.1, 3.5.5, 3.0.7 or later.");

  script_tag(name:"summary", value:"Adobe Flash Media Server is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"4.0", test_version2:"4.0.0" ) ||
    version_in_range( version:vers, test_version:"3.5", test_version2:"3.5.4" ) ||
    version_in_range( version:vers, test_version:"3.0", test_version2:"3.0.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.7/3.5.5/4.0.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
