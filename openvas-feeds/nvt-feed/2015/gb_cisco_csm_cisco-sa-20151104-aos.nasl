# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:content_security_management_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105436");
  script_cve_id("CVE-2015-6321");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2025-09-11T05:38:37+0000");

  script_name("Cisco Content Security Management Appliance AsyncOS TCP Flood Denial of Service Vulnerability (cisco-sa-20151104-aos)");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-aos");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCus79777");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling of TCP packets sent at a high rate. An attacker
  could exploit this vulnerability by sending crafted TCP packets to the affected system.");

  script_tag(name:"solution", value:"See Vendor advisory.");

  script_tag(name:"summary", value:"A vulnerability in the network stack of Cisco AsyncOS for Cisco Content Security Management
  Appliance (SMA) could allow an unauthenticated, remote attacker to exhaust all available memory, preventing the affected device
  from accepting new TCP connections.");

  script_tag(name:"affected", value:"See Vendor advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-11-06 15:21:08 +0100 (Fri, 06 Nov 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_csma_consolidation.nasl");
  script_mandatory_keys("cisco_csm/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"9.1.0-032" ) ) {
  fix = "9.1.0-032";
} else if( version_in_range( version:version, test_version:"9.1.1", test_version2:"9.1.1-004" ) ) {
  fix = "9.1.1-005";
} else if( version_in_range( version:version, test_version:"9.5.0", test_version2:"9.5.0-024" ) ) {
  fix = "9.5.0-025";
}

if( fix ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
