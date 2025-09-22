# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-605l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170313");
  script_version("2025-05-15T05:40:37+0000");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"creation_date", value:"2023-02-21 18:07:42 +0000 (Tue, 21 Feb 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 20:23:14 +0000 (Tue, 13 May 2025)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2021-40655",
                "CVE-2023-24343",
                "CVE-2023-24344",
                "CVE-2023-24345",
                "CVE-2023-24346",
                "CVE-2023-24347",
                "CVE-2023-24348",
                "CVE-2023-24349",
                "CVE-2023-24350",
                "CVE-2023-24351",
                "CVE-2023-24352",
                "CVE-2024-9532",
                "CVE-2024-9533",
                "CVE-2024-9534",
                "CVE-2024-9535",
                "CVE-2024-9549",
                "CVE-2024-9550",
                "CVE-2024-9551",
                "CVE-2024-9552",
                "CVE-2024-9553",
                "CVE-2024-9555",
                "CVE-2024-9556",
                "CVE-2024-9557",
                "CVE-2024-9558",
                "CVE-2024-9559",
                "CVE-2024-9561",
                "CVE-2024-9562",
                "CVE-2024-9563",
                "CVE-2024-9564",
                "CVE-2024-9565",
                "CVE-2024-11959",
                "CVE-2024-11960",
                "CVE-2024-37630",
                "CVE-2025-2546",
                "CVE-2025-2547",
                "CVE-2025-2548",
                "CVE-2025-2549",
                "CVE-2025-2550",
                "CVE-2025-2551",
                "CVE-2025-2552",
                "CVE-2025-2553",
                "CVE-2025-4441",
                "CVE-2025-4442",
                "CVE-2025-4443",
                "CVE-2025-4445");

  script_name("D-Link DIR-605L Multiple Vulnerabilities (2021-2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-605L devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2021-40655: Information disclosure vulnerability

  - CVE-2023-24343, CVE-2023-24344, CVE-2023-24345, CVE-2023-24346, CVE-2023-24347, CVE-2023-24348,
  CVE-2023-24349, CVE-2023-24350, CVE-2023-24351, CVE-2023-24352: multiple stack overflow
  vulnerabilities via parameters at various pages under /goform/ directory.

  - CVE-2024-9532: buffer overflow via the webpage argument of the function formDeviceReboot
  of the file /goform/formAdvanceSetup

  - CVE-2024-9533: buffer overflow via the next_page argument of the function formAdvanceSetup
  of the file /goform/formDeviceReboot

  - CVE-2024-9534: buffer overflow via the webpage argument of the function formDeviceReboot
  of the file /goform/formAdvanceSetup

  - CVE-2024-9535: buffer overflow via the curTime argument of the function formEasySetupWWConfig
  of the file /goform/formEasySetupWWConfig

  - CVE-2024-9549: buffer overflow via the curTime argument of the function
  formEasySetupWizard/formEasySetupWizard2 of the file /goform/formEasySetupWizard

  - CVE-2024-9550: buffer overflow via the curTime argument of the function formLogDnsquery of the
  file /goform/formLogDnsquery

  - CVE-2024-9551: buffer overflow via the webpage argument of the function formSetWanL2TP of the
  file /goform/formSetWanL2TP

  - CVE-2024-9552: buffer overflow via the webpage argument of the function formSetWanNonLogin of
  the file /goform/formSetWanNonLogin

  - CVE-2024-9553: buffer overflow via the curTime argument of the function formdumpeasysetup of
  the file /goform/formdumpeasysetup

  - CVE-2024-9555: buffer overflow via the curTime argument of the function formSetEasy_Wizard of
  the file /goform/formSetEasy_Wizard

  - CVE-2024-9556: buffer overflow via the curTime argument of the function formSetEnableWizard of
  the file /goform/formSetEnableWizard

  - CVE-2024-9557: buffer overflow via the webpage argument of the function formSetWanPPPoE of
  the file /goform/formSetWanPPPoE

  - CVE-2024-9558: buffer overflow via the webpage argument of the function formSetWanPPTP of
  the file /goform/formSetWanPPTP

  - CVE-2024-9559: buffer overflow via the webpage argument of the function formWlanSetup of
  the file /goform/formWlanSetup

  - CVE-2024-9561, CVE-2024-11959, CVE-2024-11960 and additional flaws without a CVE: Please see the
  references for more info

  - CVE-2024-37630: Hardcoded password

  - CVE-2025-2546, CVE-2025-2547, CVE-2025-2548, CVE-2025-2549, CVE-2025-2550, CVE-2025-2551,
  CVE-2025-2552, CVE-2025-2553: Multiple improper access control vulnerabilities at various pages
  under the /goform/ directory

  - CVE-2025-4441, CVE-2025-4442: Multiple buffer overflow vulnerabilities

  - CVE-2025-4443, CVE-2025-4445: Multiple command injection vulnerabilities");

  script_tag(name:"affected", value:"D-Link DIR-605L devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: The vendor states that technical support for DIR-605L has ended in 24.09.2019, therefore
  most probably no effort will be made to provide a fix for these vulnerabilities.");

  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/curTime_Vuls/01");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/webpage_Vuls/01");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/curTime_Vuls/03");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/02");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/webpage_Vuls/02");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/curTime_Vuls/02");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/curTime_Vuls/04");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/03");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/01");
  script_xref(name:"URL", value:"https://github.com/1160300418/Vuls/tree/main/D-Link/DIR-605L/webpage_Vuls/03");
  script_xref(name:"URL", value:"https://github.com/abcdefg-png/IoT-vulnerable/tree/main/D-Link/DIR-605L");
  script_xref(name:"URL", value:"https://github.com/offshore0315/loT-vulnerable/blob/main/D-Link/formResetStatistic.md");
  script_xref(name:"URL", value:"https://github.com/offshore0315/loT-vulnerable/blob/main/D-Link/formSetPortTr.md");
  script_xref(name:"URL", value:"https://github.com/Ilovewomen/D-LINK-DIR-605/");
  script_xref(name:"URL", value:"https://github.com/s4ndw1ch136/IOT-vuln-reports/blob/main/D-link/DIR-605L/README.md");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-605L-formAdvFirewall-1b153a41781f80aca28ec11da787f0e8?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-605L-formAdvNetwork-1b153a41781f80109325dbc96ffc0295?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-605L-formSetDomainFilter-1b153a41781f80498fcdf9d675df9b39?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-605L-formSetPassword-1b153a41781f803d8166f9b551b30cd4?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-605L-formSetDDNS-1b153a41781f80feb80bd24afc8f83d5?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-605L-formSetPortTr-1b153a41781f809d95c8e39c6c31c348?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-605L-formTcpipSetup-1b153a41781f80a7967ae08c81147a39?pvs=4");
  script_xref(name:"URL", value:"https://lavender-bicycle-a5a.notion.site/D-Link-DIR-605L-formVirtualServ-1b153a41781f80b98645c3f7f4c5f4ae?pvs=4");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10393");
  script_xref(name:"URL", value:"https://support.dlink.com/ProductInfo.aspx?m=DIR-605L");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );
