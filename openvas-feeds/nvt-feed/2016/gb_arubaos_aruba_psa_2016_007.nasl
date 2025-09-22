# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:arubanetworks:arubaos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105733");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-26 15:30:28 +0200 (Thu, 26 May 2016)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 16:06:00 +0000 (Fri, 08 Mar 2019)");

  script_cve_id("CVE-2016-0801", "CVE-2016-0802", "CVE-2015-8605");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ArubaOS Multiple Vulnerabilities (ARUBA-PSA-2016-007)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_aruba_arubaos_snmp_detect.nasl");
  script_mandatory_keys("aruba/arubaos/detected");

  script_tag(name:"summary", value:"ArubaOS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A buffer over-read vulnerability allows an unauthenticated user
  to read from uninitialized memory locations.  Based on analysis of the flaw, Aruba does not
  believe that this memory is likely to contain sensitive information.

  The Broadcom Wi-Fi driver used in the AP-2xx series access points allows attackers to execute
  arbitrary code or cause a denial of service (memory corruption) via crafted wireless control
  message packets.  The attacker must be joined to the network (wired or wireless) - this
  vulnerability may not be exercised by an unauthenticated user against a WPA2 network.

  A flaw in the ISC DHCP server allows remote attackers to cause a denial of service (application
  crash) via an invalid length field in a UDP IPv4 packet.  The flawed DHCP server is incorporated
  into ArubaOS. If the DHCP server is enabled in an Aruba mobility controller, an attacker could
  cause it to crash. ArubaOS would automatically restart the process.  However, DHCP services would
  be disrupted temporarily.");

  script_tag(name:"affected", value:"- ArubaOS 6.3 prior to 6.3.1.21

  - ArubaOS 6.4.2.x prior to 6.4.2.16

  - ArubaOS 6.4.3.x prior to 6.4.3.7

  - ArubaOS 6.4.4.x prior to 6.4.4.5");

  script_tag(name:"solution", value:"Update to version 6.3.1.21, 6.4.2.16, 6.4.3.7, 6.4.4.5 or
  later.");

  script_xref(name:"URL", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2016-007.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_in_range( version:version, test_version:"6.3", test_version2:"6.3.1.20" ) )
  fix = "6.3.1.21";

if( version_in_range( version:version, test_version:"6.4.2", test_version2:"6.4.2.15" ) )
  fix = "6.4.2.16";

if( version_in_range( version:version, test_version:"6.4.3", test_version2:"6.4.3.6" ) )
  fix = "6.4.3.7";

if( version_in_range( version:version, test_version:"6.4.4", test_version2:"6.4.4.4" ) )
  fix = "6.4.4.5";

if( fix ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
