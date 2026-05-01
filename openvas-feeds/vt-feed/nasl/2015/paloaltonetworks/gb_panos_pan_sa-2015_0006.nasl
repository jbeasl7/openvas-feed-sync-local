# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:paloaltonetworks:pan-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105453");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_version("2026-04-28T06:28:06+0000");

  script_name("Palo Alto PAN-OS API Key Automatic Revocation Vulnerability (PAN-SA-2015-0006)");

  script_xref(name:"URL", value:"https://security.paloaltonetworks.com/PAN-SA-2015-0006");

  script_tag(name:"summary", value:"An issue has been identified in PAN-OS that prevents old management API keys for local administrator accounts from being invalidated upon password change until the device is rebooted.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to PAN-OS 6.1.7, 7.0.2 or later");

  script_tag(name:"impact", value:"This issue can create a period of time during which an administrator changes the account password, thus creating a new API key, but the old API key is still valid until device reboot.");

  script_tag(name:"affected", value:"PAN-OS versions prior to PAN-OS 6.1.7 and 7.x prior to 7.0.2.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2015-11-16 10:32:56 +0100 (Mon, 16 Nov 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Palo Alto PAN-OS Local Security Checks");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_paloalto_panos_consolidation.nasl");
  script_mandatory_keys("palo_alto_pan_os/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

model = get_kb_item( "palo_alto_pan_os/model" );

if( version_is_less( version:version, test_version:"6.1.7" ) ) fix = '6.1.7';
if( version_in_range( version:version, test_version:"7.0", test_version2:"7.0.1" ) ) fix = '7.0.2';

if( fix )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     ' + fix;

  if( model )
    report += '\nModel:             ' + model;

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
