# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108923");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2020-09-02 11:07:07 +0000 (Wed, 02 Sep 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:02:00 +0000 (Tue, 16 Aug 2022)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-7494");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Cloud Multiple Products < 2.11.168 / 2.20 - 2.30 < 2.30.172 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Multiple Western Digital My Cloud products are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following issues have been addressed:

  - Resolved SMB server (samba) security vulnerability (CVE-2017-7494). Malicious clients can upload and cause the
  SMB server to execute a shared library from awritable share.

  - Resolved critical security vulnerabilities that potentially allowed unauthorized file deletion, unauthorized
  command execution and authentication bypass");

  script_tag(name:"affected", value:"Western Digital My Cloud with firmware versions prior to 2.11.168
  and 2.2 - 2.3 versions prior to 2.30.172.");

  script_tag(name:"solution", value:"Update to firmware version 2.11.168, 2.30.172 or later.

  Note: Some My Cloud products are already end-of-life and doesn't receive any updates anymore.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:wdc:my_cloud_firmware",
                     "cpe:/o:wdc:my_cloud_mirror_firmware",
                     "cpe:/o:wdc:my_cloud_pr2100_firmware",
                     "cpe:/o:wdc:my_cloud_pr4100_firmware",
                     "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
                     "cpe:/o:wdc:my_cloud_ex2_firmware",
                     "cpe:/o:wdc:my_cloud_ex4_firmware",
                     "cpe:/o:wdc:my_cloud_ex2100_firmware",
                     "cpe:/o:wdc:my_cloud_ex4100_firmware",
                     "cpe:/o:wdc:my_cloud_dl2100_firmware",
                     "cpe:/o:wdc:my_cloud_dl4100_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+")) # nb: The HTTP Detection is only able to extract the major release like 2.30
  exit(0);

version = infos["version"];

if (version_is_less(version: version, test_version: "2.11.168")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.11.168");
  security_message(port: 0, data: report);
  exit(0);
}

else if (version =~ "^2\.[23][0-9]\." && version_is_less(version: version, test_version: "2.30.172")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.30.172");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
