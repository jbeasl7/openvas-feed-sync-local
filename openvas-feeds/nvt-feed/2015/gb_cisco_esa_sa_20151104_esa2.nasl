# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:email_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105445");
  script_cve_id("CVE-2015-6291");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Email Security Appliance Email Scanner Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-esa2");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper input validation when an email attachment contains corrupted fields and is filtered by the ESA. An attacker could exploit this vulnerability by sending a crafted email with an attachment to the ESA. A successful exploit could allow the attacker to cause a DoS condition. While the attachment is being filtered, memory is consumed at at high rate until the filtering process restarts. When the process restarts, it will resume processing the same malformed attachment and the DoS condition will continue.
Cisco has released software updates that address this vulnerability. There are no workarounds that mitigate this vulnerability.");

  script_tag(name:"solution", value:"See Vendor advisory.");
  script_tag(name:"summary", value:"A vulnerability in the email message filtering feature of Cisco AsyncOS for Cisco Email Security Appliance (ESA) could allow an unauthenticated, remote attacker to cause an ESA device to become unavailable due to a denial of service (DoS) condition.");

  script_tag(name:"affected", value:"See Vendor advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-10 11:02:51 +0100 (Tue, 10 Nov 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_esa_version.nasl");
  script_mandatory_keys("cisco_esa/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

version = str_replace( string:version, find:"-", replace:"." );

if( version_is_less(  version:version, test_version:"8.5.7.043" ) ) fix = '8.5.7-043';
if( version_in_range( version:version, test_version:"9.0", test_version2:"9.1.1.022" ) ) fix = '9.1.1-023';
if( version_in_range( version:version, test_version:"9.5", test_version2:"9.6.0.045" ) ) fix = '9.6.0-046';

if( fix )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     ' + fix + '\n';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

