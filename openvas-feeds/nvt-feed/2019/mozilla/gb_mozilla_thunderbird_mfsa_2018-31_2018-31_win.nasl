# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814830");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-17466", "CVE-2018-18492", "CVE-2018-18493", "CVE-2018-18494",
                "CVE-2018-18498", "CVE-2018-12405");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-11 15:00:00 +0000 (Mon, 11 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-01-25 15:15:03 +0530 (Fri, 25 Jan 2019)");
  script_name("Mozilla Thunderbird Security Advisory (MFSA2018-31) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Buffer overflow and out-of-bounds read errors in TextureStorage11 within the
    ANGLE graphics library.

  - A use-after-free error with select element.

  - A buffer overflow error in accelerated 2D canvas with Skia.

  - A same-origin policy violation allowing the theft of cross-origin URL entries.

  - An integer overflow error when calculating buffer sizes for images.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  crash the application, cause out-of-bounds write, steal data and run arbitrary
  code.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 60.4 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 60.4
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-31");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"60.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"60.4", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
