# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:mobility_services_engine";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105463");
  script_cve_id("CVE-2015-6316", "CVE-2015-4282");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_version("2025-01-17T15:39:18+0000");

  script_name("Cisco Mobility Services Engine (MSE) Multiple Vulnerabilities (cisco-sa-20151104-privmse, cisco-sa-20151104-mse-cred)");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-privmse");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77432");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77435");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-mse-cred");

  script_tag(name:"summary", value:"Cisco Mobility Services Engine (MSE) is prone multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - an insecure default-password vulnerability

  Remote attackers with knowledge of the default credentials may exploit this vulnerability to gain
  unauthorized access and perform unauthorized actions. This may aid in further attacks.

  - a local privilege escalation vulnerability

  A local attacker may exploit this issue to gain elevated root privileges on the device.

  These issues are being tracked by Cisco Bug ID CSCuv40501 and CSCuv40504.");

  script_tag(name:"affected", value:"Cisco Mobility Services Engine (MSE) versions 8.0.120.7 and
  earlier are vulnerable.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-11-20 14:02:20 +0100 (Fri, 20 Nov 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_mse_cmx_version.nasl");
  script_mandatory_keys("cisco_mse/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( version_is_less_equal( version:version, test_version:"8.0.120.7" ) ) {
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     See vendor advisory';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
