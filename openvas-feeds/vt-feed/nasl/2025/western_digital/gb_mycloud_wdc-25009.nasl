# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128192");
  script_version("2026-04-15T06:17:01+0000");
  script_tag(name:"last_modification", value:"2026-04-15 06:17:01 +0000 (Wed, 15 Apr 2026)");
  script_tag(name:"creation_date", value:"2025-12-22 03:26:39 +0000 (Mon, 22 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-18 19:15:29 +0000 (Tue, 18 Feb 2025)");

  script_cve_id("CVE-2025-26465");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products Multiple Vulnerabilities (WDC-25009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-26465: A vulnerability was found in OpenSSH when the VerifyHostKeyDNS option is
  enabled. A machine-in-the-middle attack can be performed by a malicious machine impersonating a
  legit server. This issue occurs due to how OpenSSH mishandles error codes in specific conditions
  when verifying the host key. For an attack to be considered successful, the attacker needs to
  manage to exhaust the client's memory resource first, turning the attack complexity high.

  - No CVE: Implemented a fix for a security flaw, reducing exposure to potential threats.");

  script_tag(name:"affected", value:"Western Digital My Cloud PR2100, My Cloud PR4100,
  My Cloud EX4100, My Cloud EX2 Ultra, My Cloud Mirror Gen 2, My Cloud DL2100, My Cloud EX2100,
  My Cloud DL4100, My Cloud WDBCTLxxxxxx-10, WD Cloud with firmware prior to version
  5.32.102.");

  script_tag(name:"solution", value:"Update to firmware version 5.32.102 or later.");

  script_xref(name:"URL", value:"https://www.westerndigital.com/support/product-security/wdc-25009-western-digital-my-cloud-os-5-firmware-5-32-102");
  script_xref(name:"URL", value:"https://os5releasenotes.mycloud.com/#5.32.102");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:wd_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_mirror_gen2_firmware",
                     "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
                     "cpe:/o:wdc:my_cloud_ex2100_firmware",
                     "cpe:/o:wdc:my_cloud_ex4100_firmware",
                     "cpe:/o:wdc:my_cloud_dl2100_firmware",
                     "cpe:/o:wdc:my_cloud_dl4100_firmware",
                     "cpe:/o:wdc:my_cloud_pr2100_firmware",
                     "cpe:/o:wdc:my_cloud_pr4100_firmware",
                     "cpe:/o:wdc:my_cloud_wdbctlxxxxxx-10_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+(\.[0-9]+)?$")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];


if (version_is_less(version: version, test_version: "5.32.102")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.32.102");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
