# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:avm:fritz%21_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108808");
  script_version("2025-09-10T05:38:24+0000");
  script_cve_id("CVE-2019-15126");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 19:15:00 +0000 (Tue, 11 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-06-29 10:38:30 +0000 (Mon, 29 Jun 2020)");
  script_name("AVM FRITZ!Box 7581 and 7582 < 7.13 Information Disclosure Vulnerability (Kr00k)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_dependencies("gb_avm_fritz_box_consolidation.nasl");
  script_mandatory_keys("avm/fritz/model", "avm/fritz/firmware_version");

  script_xref(name:"URL", value:"https://en.avm.de/service/current-security-notifications/");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/156809/Broadcom-Wi-Fi-KR00K-Proof-Of-Concept.html");
  script_xref(name:"URL", value:"https://www.eset.com/int/kr00k/");
  script_xref(name:"URL", value:"https://www.welivesecurity.com/wp-content/uploads/2020/02/ESET_Kr00k.pdf");

  script_tag(name:"summary", value:"AVM FRITZ!Box 7581 and 7582 devices are prone to an information
  disclosure vulnerability dubbed 'Kr00k'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered on Broadcom Wi-Fi client devices.

  Specifically timed and handcrafted traffic can cause internal errors (related to state
  transitions) in a WLAN device.");

  script_tag(name:"impact", value:"The flaw lead to improper layer 2 Wi-Fi encryption with a
  consequent possibility of information disclosure over the air for a discrete set of traffic.");

  script_tag(name:"affected", value:"AVM FRITZ!Box 7581 and 7582 devices running AVM FRITZ!OS before
  version 7.13.");

  script_tag(name:"solution", value:"Update to AVM FRITZ!OS 7.13 or later.");

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

fixes = make_array( "7581", "7.13",
                    "7582", "7.13" );

if( ! fixes[model] )
  exit( 99 );

patch = fixes[model];

if( version_is_less( version:fw_version, test_version:patch ) ) {
  report  = 'Model:              ' + model + '\n';
  report += 'Installed Firmware: ' + fw_version + '\n';
  report += 'Fixed Firmware:     ' + patch;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
