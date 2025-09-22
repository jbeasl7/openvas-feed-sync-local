# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-619l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128077");
  script_version("2025-08-19T05:39:49+0000");
  script_tag(name:"last_modification", value:"2025-08-19 05:39:49 +0000 (Tue, 19 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-01-08 10:51:15 +0000 (Wed, 08 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 18:27:48 +0000 (Tue, 13 May 2025)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2024-33771",
                "CVE-2024-33772",
                "CVE-2024-33773",
                "CVE-2024-33774",
                "CVE-2024-9908",
                "CVE-2024-9909",
                "CVE-2024-9910",
                "CVE-2024-9911",
                "CVE-2024-9912",
                "CVE-2024-9913",
                "CVE-2024-9914",
                "CVE-2024-9915",
                "CVE-2024-9566",
                "CVE-2024-9567",
                "CVE-2024-9568",
                "CVE-2024-9569",
                "CVE-2024-9570",
                "CVE-2024-9782",
                "CVE-2024-9783",
                "CVE-2024-9784",
                "CVE-2024-9785",
                "CVE-2024-9786",
                "CVE-2025-4448",
                "CVE-2025-4449",
                "CVE-2025-4450",
                "CVE-2025-4451",
                "CVE-2025-4452",
                "CVE-2025-4453",
                "CVE-2025-4454",
                "CVE-2025-6114",
                "CVE-2025-6115",
                "CVE-2025-6367",
                "CVE-2025-6368",
                "CVE-2025-6369",
                "CVE-2025-6370",
                "CVE-2025-6371",
                "CVE-2025-6372",
                "CVE-2025-6373",
                "CVE-2025-6374",
                "CVE-2025-6614",
                "CVE-2025-6615",
                "CVE-2025-6616",
                "CVE-2025-6617",
                "CVE-2025-8978"
               );

  script_name("D-Link DIR-619L Multiple Vulnerabilities (2024 - 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-619L devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-33771: Buffer overflow via goform/formWPS

  - CVE-2024-33772: Buffer overflow via formTcpipSetup

  - CVE-2024-33773: Buffer overflow via formWlanGuestSetup

  - CVE-2024-33774: Buffer overflow via formWlanSetup_Wizard

  - CVE-2024-9908: Buffer overflow via formSetMACFilter

  - CVE-2024-9909: Buffer overflow via formSetMuti

  - CVE-2024-9910: Buffer overflow via formSetPassword

  - CVE-2024-9911: Buffer overflow via formSetPortTr

  - CVE-2024-9912: Buffer overflow via formSetQoS

  - CVE-2024-9913: Buffer overflow via formSetRoute

  - CVE-2024-9914: Buffer overflow via formSetWizardSelectMode

  - CVE-2024-9915: Buffer overflow via formVirtualServ

  - CVE-2024-9566: Buffer overflow via formDeviceReboot

  - CVE-2024-9567: Buffer overflow via formAdvFirewall

  - CVE-2024-9568: Buffer overflow via formAdvNetwork

  - CVE-2024-9569: Buffer overflow via formEasySetPassword

  - CVE-2024-9570: Buffer overflow via formEasySetTimezone

  - CVE-2024-9782: Buffer overflow via formEasySetupWWConfig

  - CVE-2024-9783: Buffer overflow via formLogDnsquery

  - CVE-2024-9784: Buffer overflow via formResetStatistic

  - CVE-2024-9785: Buffer overflow via formSetDDNS

  - CVE-2024-9786: Buffer overflow via formSetLog

  - CVE-2025-4448, CVE-2025-4449, CVE-2025-4450, CVE-2025-4451, CVE-2025-4452, CVE-2025-4453,
  CVE-2025-4454: Multiple buffer overflows in various functions

  - CVE-2025-6114, CVE-2025-6115, CVE-2025-6367, CVE-2025-6368, CVE-2025-6369, CVE-2025-6370,
  CVE-2025-6371, CVE-2025-6372, CVE-2025-6373, CVE-2025-6374: Stack-based buffer overflow

  - CVE-2025-6614, CVE-2025-6615, CVE-2025-6616, CVE-2025-6617: Stack overflow

  - CVE-2025-8978: Insufficient verification of data authenticity during firmware update");

  script_tag(name:"affected", value:"D-Link DIR-619L devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that the model reached its End-of-Support Date, is no longer
  supported, and firmware development has ceased.");

  script_xref(name:"URL", value:"https://www.dlinkmea.com/index.php/product/details?det=RHlTazJFdkJ4STJQSzN5YmluTTJsQT09");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formDeviceReboot.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formAdvFirewall.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formAdvNetwork.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formEasySetPassword.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formEasySetTimezone.md.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formEasySetupWWConfig.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formLogDnsquery.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formResetStatistic.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formSetDDNS.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formSetLog.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formSetMuti.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formSetMACFilter.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formSetPassword.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formSetPortTr.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formSetWizardSelectMode.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formSetQoS.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formSetRoute.md");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/blob/main/D-Link/DIR-619L/formVirtualServ.md");
  script_xref(name:"URL", value:"https://github.com/YuboZhaoo/IoT/blob/main/D-Link/DIR-619L/20240424.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_60/60.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_62/62.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_67/67.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_68/68.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_69/69.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_70/70.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_71/71.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_72/72.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_73/73.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_74/74.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_75/75.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_76/76.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_77/77.md");
  script_xref(name:"URL", value:"https://github.com/wudipjq/my_vuln/blob/main/D-Link6/vuln_78/78.md");
  script_xref(name:"URL", value:"https://github.com/IOTRes/IOT_Firmware_Update/blob/main/Dlink/DIR619L.md");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

# nb: Device is very old model and EOL since at least 2019
report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );
