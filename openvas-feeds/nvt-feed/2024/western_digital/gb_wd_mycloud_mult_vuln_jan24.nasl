# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114299");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-01-23 10:45:44 +0000 (Tue, 23 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 14:27:09 +0000 (Tue, 13 Feb 2024)");

  script_cve_id("CVE-2023-22817", "CVE-2023-22819");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products 5.x < 5.27.161 Multiple Vulnerabilities (WDC-24001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-22817: Addressed a server-side request forgery vulnerability by fixing DNS addresses
  that refer to loopback. This could allow a rogue server on the local network to modify its URL
  using another DNS address to point back to the loopback adapter. This could then allow the URL to
  exploit other vulnerabilities on the local server.

  - CVE-2023-22819: Addressed an uncontrolled resource consumption issue on a particular endpoint
  that could arise by sending crafted requests to a service to consume a large amount of memory,
  eventually resulting in the service being stopped and restarted.");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100, My Cloud EX2
  Ultra, My Cloud EX4100, My Cloud Mirror Gen 2, My Cloud EX2100, My Cloud DL2100, My Cloud DL4100,
  My Cloud and WD Cloud with firmware prior to version 5.27.161.");

  script_tag(name:"solution", value:"Update to firmware version 5.27.161 or later.");

  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-24001-western-digital-my-cloud-os-5-my-cloud-home-duo-and-sandisk-ibi-firmware-update");
  script_xref(name:"URL", value:"https://os5releasenotes.mycloud.com/#5.27.161");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-24-088/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-24-087/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.27.161")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.27.161");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
