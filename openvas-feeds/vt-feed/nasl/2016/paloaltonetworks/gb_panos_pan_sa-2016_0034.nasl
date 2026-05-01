# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:paloaltonetworks:pan-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140074");
  script_cve_id("CVE-2016-9151");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2026-04-28T06:28:06+0000");

  script_name("Palo Alto PAN-OS Local Privilege Escalation (PAN-SA-2016-0034)");

  script_xref(name:"URL", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/67");

  script_tag(name:"summary", value:"Palo Alto Networks firewalls do not properly validate certain environment variables which can potentially allow executing code with higher privileges. A potential attacker with local shell access could manipulate arbitrary environment variables which could result in a process running with higher privileges.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to PAN-OS 5.0.20 and later, PAN-OS 5.1.13 and later, PAN-OS 6.0.15 and later, PAN-OS 6.1.15 and later, PAN-OS 7.0.11 and later, PAN-OS 7.1.6 and later.");

  script_tag(name:"affected", value:"PAN-OS 5.0.19 and earlier, PAN-OS 5.1.12 and earlier, PAN-OS 6.0.14 and earlier, PAN-OS 6.1.14 and earlier, PAN-OS 7.0.10 and earlier, PAN-OS 7.1.5 and earlier.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-17 16:15:00 +0000 (Mon, 17 Feb 2020)");
  script_tag(name:"creation_date", value:"2016-11-21 11:18:24 +0100 (Mon, 21 Nov 2016)");
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
else if( version =~ "^6\.1" )
  fix = '6.1.15';
else if( version =~ "^7\.0" )
  fix = '7.0.11';
else if( version =~ "^7\.1" )
  fix = '7.1.6';

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
