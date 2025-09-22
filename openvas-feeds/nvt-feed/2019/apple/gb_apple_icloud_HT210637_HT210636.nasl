# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815496");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-8745", "CVE-2019-8625", "CVE-2019-8719", "CVE-2019-8707",
                "CVE-2019-8763", "CVE-2019-8726", "CVE-2019-8733", "CVE-2019-8735");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-10-10 11:25:57 +0530 (Thu, 10 Oct 2019)");
  script_name("Apple iCloud Security Updates (HT210637_HT210636)");

  script_tag(name:"summary", value:"Apple iCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overflow error due to improper bounds checking.

  - A logic issue due to improper state management.

  - Multiple memory corruption issues due to improper memory handling.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to conduct cross site scripting attacks and execute arbitrary code by processing
  maliciously crafted web content.");

  script_tag(name:"affected", value:"Apple iCloud versions before 7.14 and
  10.x before 10.7 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 7.14 or 10.7 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210637");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210636");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_icloud_detect_win.nasl");
  script_mandatory_keys("apple/icloud/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.14")) {
  fix = "7.14";
}

else if(vers =~ "^10\." && version_is_less(version:vers, test_version:"10.7")) {
  fix = "10.7";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
