# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105744");
  script_cve_id("CVE-2016-1405");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 19:58:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-06-01 12:15:36 +0200 (Wed, 01 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cisco WSA AMP ClamAV Denial of Service Vulnerability");

  script_tag(name:"summary", value:"A vulnerability in the Clam AntiVirus (ClamAV) software that is used by Cisco Advance Malware Protection (AMP) for Cisco Email Security Appliances (ESAs) and Cisco Web Security Appliances (WSAs) could allow an unauthenticated, remote attacker to cause the AMP process to restart.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"See advisory");

  script_tag(name:"solution", value:"This vulnerability is addressed in the following Cisco AsyncOS Software releases: 9.0.1-135 and later / 9.1.1-041 and later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160531-wsa-esa");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

version = str_replace( string:vers, find:"-", replace:"." );

if( version =~ "^8\." ) fix = '9.0.1-135';

if( version =~ "^9\.0" )
  if( version_is_less( version:version, test_version:"9.0.1.135" ) ) fix = '9.0.1-135';

if( version =~ "^9\.1" )
  if( version_is_less( version:version, test_version:"9.1.1.041" ) ) fix = '9.1.1-041';

if( version == " 9.5.0.284" ) fix = "Ask vendor";

if( fix )
{
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}
