# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:arubanetworks:arubaos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105657");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-06 16:08:57 +0200 (Fri, 06 May 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2015-5437");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ArubaOS Multiple Vulnerabilities (ARUBA-PSA-2015-011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_aruba_arubaos_snmp_detect.nasl");
  script_mandatory_keys("aruba/arubaos/detected");

  script_tag(name:"summary", value:"ArubaOS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A reflected cross-site scripting vulnerability is present in the a monitoring page in the
  WebUI. If an administrator were tricked into clicking on a malicious URL while logged into an
  Aruba controller's management interface, this vulnerability could potentially reveal a session
  cookie.

  - Most configuration-related pages in the ArubaOS management UI are protected against cross-site
  request forgery (CSRF) through the use of a unique, random token. It was found that certain
  operations which could reveal sensitive information, such as the controller configuration file,
  were not protected against CSRF.  If an administrator were tricked into clicking on a malicious
  URL while logged into an Aruba controller's management interface, this vulnerability could leak
  sensitive information to an attacker.

  - Sending a specific malformed wireless frame to an AP-225 may cause the AP to reboot. Aruba
  inadvertently documented this in ArubaOS release notes before a security advisory could be
  issued.");

  script_tag(name:"affected", value:"- ArubaOS 6.3 up to, but not including, 6.3.1.19

  - ArubaOS 6.4 up to, but not including, 6.4.2.13 and 6.4.3.4");

  script_tag(name:"solution", value:"Update to version 6.3.1.19, 6.4.2.13, 6.4.3.4, 6.4.4.0 or
  later.");

  script_xref(name:"URL", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2015-011.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_in_range( version:version, test_version:"6.3", test_version2:"6.3.1.18" ) )
  fix = "6.3.1.19";

if( version_in_range( version:version, test_version:"6.4.2", test_version2:"6.4.2.12" ) )
  fix = "6.4.2.13";

if( version_in_range( version:version, test_version:"6.4.3", test_version2:"6.4.3.3" ) )
  fix = "6.4.3.4";

if( fix ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
