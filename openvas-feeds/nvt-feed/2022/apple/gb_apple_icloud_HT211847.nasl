# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826558");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2020-36521", "CVE-2020-9991", "CVE-2020-15358", "CVE-2020-9952");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-09 16:41:00 +0000 (Tue, 09 Mar 2021)");
  script_tag(name:"creation_date", value:"2022-09-28 09:52:31 +0530 (Wed, 28 Sep 2022)");
  script_name("Apple iCloud Security Update (HT211847)");

  script_tag(name:"summary", value:"Apple iCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple input validation errors.

  - Improper checks.

  - Multiple issues in SQLite.");

  script_tag(name:"impact", value:"Successful exploitation allow remote attackers
  to cause denial of service and conduct cross site scripting attack.");

  script_tag(name:"affected", value:"Apple iCloud versions before 7.21");

  script_tag(name:"solution", value:"Upgrade to Apple iCloud version 7.21 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT211847");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"7.21")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.21", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
