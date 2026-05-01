# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:paloaltonetworks:pan-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140016");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2026-04-28T06:28:06+0000");
  script_cve_id("CVE-2015-5364", "CVE-2015-5366");
  script_name("Palo Alto PAN-OS Kernel Vulnerabilities (PAN-SA-2016-0025)");

  script_xref(name:"URL", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/58");

  script_tag(name:"summary", value:"The kernel in use by the Management Plane of PAN-OS is vulnerable to CVE-2015-5364 and CVE-2015-5366.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to PAN-OS 5.0.20 and later, PAN-OS 5.1.13 and later, PAN-OS 6.0.15 and later, PAN-OS 7.0.11 and later, PAN-OS 7.1.5 and later.");

  script_tag(name:"affected", value:"PAN-OS 5.0.19 and earlier, PAN-OS 5.1.12 and earlier, PAN-OS 6.0.14 and earlier, PAN-OS 6.1.X, PAN-OS 7.0.10 and prior, PAN-OS 7.1.4 and earlier.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2016-10-25 14:26:55 +0200 (Tue, 25 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Palo Alto PAN-OS Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_paloalto_panos_consolidation.nasl");
  script_mandatory_keys("palo_alto_pan_os/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

model = get_kb_item( "palo_alto_pan_os/model" );

if( version =~ "^5\.0" )
  fix = '5.0.20';
else if( version =~ "^5\.1" )
  fix = '5.1.13';
else if( version =~ "^6\.0" )
  fix = '6.0.15';
else if( version =~ "^7\.0" )
  fix = '7.0.11';
else if( version =~ "^7\.1" )
  fix = '7.1.5';

if( ! fix ) exit( 0 );

if( version_is_less( version:version, test_version:fix ) )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     ' + fix;

  if( model )
    report += '\nModel:             ' + model;

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
