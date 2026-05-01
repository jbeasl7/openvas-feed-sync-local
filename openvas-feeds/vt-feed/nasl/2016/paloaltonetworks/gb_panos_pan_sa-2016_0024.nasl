# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:paloaltonetworks:pan-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105896");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2026-04-28T06:28:06+0000");

  script_name("Palo Alto PAN-OS Web Interface DoS Vulnerability (PAN-SA-2016-0024)");

  script_xref(name:"URL", value:"https://security.paloaltonetworks.com/PAN-SA-2016-0024");

  script_tag(name:"summary", value:"Palo Alto Networks firewalls offer a web interface to manage all aspects of the device. A denial of service condition was identified in this process");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to PAN-OS 5.1.12 and later, PAN-OS 6.0.14 and later, PAN-OS 6.1.13 and later, PAN-OS 7.0.9 and later, PAN-OS 7.1.3 and later.");

  script_tag(name:"impact", value:"A third party could remotely disrupt the web management process and cause a management delay before the device resumes normal management operations.");

  script_tag(name:"affected", value:"PAN-OS 5.1.11 and earlier, PAN-OS 6.0.13 and earlier, PAN-OS 6.1.12 and earlier, PAN-OS 7.0.8 and earlier, PAN-OS 7.1.2 and earlier.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2016-09-19 13:52:47 +0200 (Mon, 19 Sep 2016)");
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

if( version =~ "^5\.1" )
  fix = '5.1.12';
else if( version =~ "^6\.0" )
  fix = '6.0.14';
else if( version =~ "^6\.1" )
  fix = '6.1.13';
else if( version =~ "^7\.0" )
  fix = '7.0.9';
else if( version =~ "^7\.1" )
  fix = '7.1.3';

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
