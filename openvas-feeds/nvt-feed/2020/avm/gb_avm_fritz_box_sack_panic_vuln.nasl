# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:avm:fritz%21_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108951");
  script_version("2025-09-10T05:38:24+0000");
  script_cve_id("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-17 21:28:00 +0000 (Tue, 17 Jan 2023)");
  script_tag(name:"creation_date", value:"2020-10-20 06:02:28 +0000 (Tue, 20 Oct 2020)");
  script_name("AVM FRITZ!Box TCP SACK PANIC - Kernel Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_dependencies("gb_avm_fritz_box_consolidation.nasl");
  script_mandatory_keys("avm/fritz/model", "avm/fritz/firmware_version");

  script_xref(name:"URL", value:"https://en.avm.de/service/security-information-about-updates/");
  script_xref(name:"URL", value:"https://access.redhat.com/security/vulnerabilities/tcpsack");

  script_tag(name:"summary", value:"Multiple AVM FRITZ!Box devices are prone to multiple Denial of Service
  vulnerabilities.");

  script_tag(name:"insight", value:"Three related flaws were found in the Linux kernel's handling of TCP Selective
  Acknowledgement (SACK) packets handling with low MSS size.");

  script_tag(name:"impact", value:"The extent of impact is understood to be limited to denial of service at this
  time. No privilege escalation or information leak is currently suspected");

  script_tag(name:"affected", value:"AVM FRITZ!Box devices running AVM FRITZ!OS before version 7.12.");

  script_tag(name:"vuldetect", value:"Check the AVM FRITZ!OS version.");

  script_tag(name:"solution", value:"Update to AVM FRITZ!OS 7.12 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! fw_version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! model = get_kb_item( "avm/fritz/model" ) )
  exit( 0 );

patch = "7.12";

if( version_is_less( version:fw_version, test_version:patch ) ) {
  report  = 'Model:              ' + model + '\n';
  report += 'Installed Firmware: ' + fw_version + '\n';
  report += 'Fixed Firmware:     ' + patch;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
