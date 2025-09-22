# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154438");
  script_version("2025-05-16T15:42:04+0000");
  script_tag(name:"last_modification", value:"2025-05-16 15:42:04 +0000 (Fri, 16 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-06 03:38:05 +0000 (Tue, 06 May 2025)");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 17:55:33 +0000 (Wed, 09 Nov 2022)");

  # nb: Vendor advisory only includes CVE-2021-29476 but as seen on e.g.:
  # https://security-tracker.debian.org/tracker/CVE-2021-29476:
  # > The CVE directly correspond to CVE-2020-28032 for wordpress and we can track same versions as
  # fixed. Strictly speaking CVE-2021-29476 is for the PHP Requests library directly.
  # As the WordPress app in MyCloud got fixed we can also include the WordPress CVE here.
  script_cve_id("CVE-2021-29921", "CVE-2015-20107", "CVE-2022-45061", "CVE-2023-24329",
                "CVE-2021-3737", "CVE-2023-6597", "CVE-2024-0450", "CVE-2021-28861",
                "CVE-2022-0391", "CVE-2022-26488", "CVE-2020-10735", "CVE-2021-29476",
                "CVE-2020-28032");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.x < 5.31.101 Multiple Vulnerabilities (WDC-25003)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to
  multiple vulnerabilities in various third-party components (Python3, Requests, WordPress).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100,
  My Cloud Mirror Gen 2, My Cloud EX4100, My Cloud EX2100, My Cloud EX2 Ultra, My Cloud DL4100,
  My Cloud and WD Cloud with firmware prior to version 5.31.101.");

  script_tag(name:"solution", value:"Update to firmware version 5.31.101 or later.");

  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/WDC-25003-western-digital-my-cloud-os-5-firmware-5-31-101");
  script_xref(name:"URL", value:"https://os5releasenotes.mycloud.com/#5.31.101");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.31.101")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.31.101");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
