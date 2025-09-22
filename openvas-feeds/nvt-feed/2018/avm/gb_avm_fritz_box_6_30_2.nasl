# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:avm:fritz%21_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108461");
  script_version("2025-09-10T05:38:24+0000");
  script_cve_id("CVE-2014-8886", "CVE-2015-7242");
  script_name("AVM FRITZ!OS < 6.30 Multiple Vulnerabilities");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:54:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2018-09-16 12:40:52 +0200 (Sun, 16 Sep 2018)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_avm_fritz_box_consolidation.nasl");
  script_mandatory_keys("avm/fritz/firmware_version");

  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/advisories/rt-sa-2014-014");
  script_xref(name:"URL", value:"http://ds-develop.de/advisories/advisory-2016-01-07-1-avm.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/135168/AVM-FRITZ-OS-HTML-Injection.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/135161/AVM-FRITZ-Box-Arbitrary-Code-Execution-Via-Firmware-Images.html");

  script_tag(name:"summary", value:"AVM FRITZ!Box devices running AVM FRITZ!OS before 6.30 are prone
  multiple vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - the content extraction of firmware updates before verifying their cryptographic signature

  - a cross-site scripting (XSS) vulnerability in the Push-Service-Mails feature via the display name
  in the FROM field of an SIP INVITE message.");

  script_tag(name:"impact", value:"An remote attacker might be able to:

  - to create symlinks or overwrite critical files, and consequently execute arbitrary code,
  via a crafted firmware image.

  - to inject arbitrary web script or HTML.");

  script_tag(name:"vuldetect", value:"Check the AVM FRITZ!OS version.");

  script_tag(name:"solution", value:"Update the AVM FRITZ!OS to 6.30 or higher.");

  script_tag(name:"affected", value:"AVM FRITZ!OS before 6.30.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! fw_version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

# nb: No detailed list on affected/fixed models thus a model independent VT was created
patch = "6.30";
if( version_is_less( version:fw_version, test_version:patch ) ) {

  if( model = get_kb_item( "avm/fritz/model" ) )
    report  = 'Model:              ' + model + '\n';

  report += 'Installed Firmware: ' + fw_version + '\n';
  report += 'Fixed Firmware:     ' + patch;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
