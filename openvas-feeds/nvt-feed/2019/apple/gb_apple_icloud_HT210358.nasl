# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815262");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2019-13118", "CVE-2019-8658", "CVE-2019-8690", "CVE-2019-8644",
                "CVE-2019-8666", "CVE-2019-8669", "CVE-2019-8671", "CVE-2019-8672",
                "CVE-2019-8673", "CVE-2019-8676", "CVE-2019-8677", "CVE-2019-8678",
                "CVE-2019-8679", "CVE-2019-8680", "CVE-2019-8681", "CVE-2019-8683",
                "CVE-2019-8684", "CVE-2019-8685", "CVE-2019-8686", "CVE-2019-8687",
                "CVE-2019-8688", "CVE-2019-8689", "CVE-2019-8649");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-18 13:01:00 +0000 (Tue, 18 May 2021)");
  script_tag(name:"creation_date", value:"2019-07-24 16:08:55 +0530 (Wed, 24 Jul 2019)");
  script_name("Apple iCloud Security Updates (HT210358)");

  script_tag(name:"summary", value:"Apple iCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A stack overflow issue.

  - Multiple logic issues in the handling of document loads and synchronous page loads.

  - Multiple memory corruption issues.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to view sensitive information, conduct cross site scripting attacks and execute
  arbitrary code by processing maliciously crafted web content.");

  script_tag(name:"affected", value:"Apple iCloud version 10.x before 10.6 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud 10.6 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210358");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT204283");
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

if(vers =~ "^10\." && version_is_less(version:vers, test_version:"10.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.6", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
