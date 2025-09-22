# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149047");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2023-01-02 05:23:47 +0000 (Mon, 02 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-21 13:05:00 +0000 (Wed, 21 Jun 2023)");

  script_cve_id("CVE-2022-36331");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.x < 5.25.132 Authentication Bypass Vulnerability (WDC-22020)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to an
  authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Western Digital My Cloud devices are vulnerable to an
  impersonation attack that could allow an unauthenticated attacker to gain access to user data.");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100, My Cloud
  EX4100, My Cloud EX2 Ultra, My Cloud Mirror Gen 2, My Cloud DL2100, My Cloud DL4100, My Cloud
  EX2100, My Cloud and WD Cloud with firmware prior to version 5.25.132.");

  script_tag(name:"solution", value:"Update to firmware version 5.25.132 or later.");

  script_xref(name:"URL", value:"https://os5releasenotes.mycloud.com/#5.25.132");
  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-22020-my-cloud-os-5-my-cloud-home-ibi-firmware-update");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.25.132")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.25.132");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
