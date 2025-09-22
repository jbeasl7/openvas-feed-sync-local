# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154073");
  script_version("2025-04-25T05:39:37+0000");
  script_tag(name:"last_modification", value:"2025-04-25 05:39:37 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-02-25 02:41:35 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-25 13:24:03 +0000 (Wed, 25 Oct 2023)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-4911", "CVE-2023-4154", "CVE-2023-38545", "CVE-2023-38546");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.x < 5.30.103 Multiple Vulnerabilities (WDC-25001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-4911: Updated open-source GLIBC package which allowed a local attacker to use
  maliciously crafted GLIBC_TUNABLES environment variables when launching binaries with SUID
  permission to execute code with elevated privileges.

  - CVE-2023-4154: Updated open-source Samba package which exposed passwords and secrets to users
  with privileges and Read-Only Domain Controllers.

  - CVE-2023-38545, CVE-2023-38546: Updated open-source curl package which crashed curl application
  because of heap-based overflow and which allows an attacker to insert cookies at will into a
  running program using libcurl, if the specific series of conditions are met.");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100, My Cloud EX2
  Ultra, My Cloud EX4100, My Cloud Mirror Gen 2, My Cloud EX2100, My Cloud DL2100, My Cloud DL4100,
  My Cloud and WD Cloud with firmware prior to version 5.30.103.");

  script_tag(name:"solution", value:"Update to firmware version 5.30.103 or later.");

  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-25001-western-digital-my-cloud-os-5-firmware-5-30-103");
  script_xref(name:"URL", value:"https://os5releasenotes.mycloud.com/#5.30.103");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-m77w-6vjw-wh2f");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2023-4154.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-38545.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-38546.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:wd_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
                     "cpe:/o:wdc:my_cloud_ex2100_firmware",
                     "cpe:/o:wdc:my_cloud_ex4100_firmware",
                     "cpe:/o:wdc:my_cloud_dl2100_firmware",
                     "cpe:/o:wdc:my_cloud_dl4100_firmware",
                     "cpe:/o:wdc:my_cloud_pr2100_firmware",
                     "cpe:/o:wdc:my_cloud_pr4100_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.30.103")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.30.103");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
