# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105779");
  script_cve_id("CVE-2016-1440");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-06-28 14:05:06 +0200 (Tue, 28 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cisco Web Security Appliance Native FTP Denial of Service Vulnerability");

  script_tag(name:"summary", value:"A vulnerability in the native pass-through FTP functionality of the Cisco Web Security Appliance (WSA) could allow an unauthenticated, remote attacker to cause a partial denial of service (DoS) condition due to high CPU utilization.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Cisco WSA < 9.1.1-041");

  script_tag(name:"solution", value:"Update to 9.1.1-041 or newer");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160627-wsa");

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

if( version_is_less( version:version, test_version:'9.1.1.041' ) )
{
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.1.1-041" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
