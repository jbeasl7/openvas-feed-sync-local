# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:powershell";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821327");
  script_version("2025-09-05T15:40:40+0000");
  script_cve_id("CVE-2022-41076");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-13 19:25:00 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-14 15:45:33 +0530 (Wed, 14 Dec 2022)");
  script_name("Microsoft PowerShell Remote Code Execution Vulnerability (Dec 2022) - Windows");

  script_tag(name:"summary", value:"This host is missing an important security update for PowerShell
  Core according to Microsoft security advisory CVE-2022-41076.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when specially crafted ANSI control sequences
  are used through the pipeline to create executable code.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute the
  code.");

  script_tag(name:"affected", value:"PowerShell Core versions 7.2 through 7.2.7 and 7.3.0 on
  Windows.");

  script_tag(name:"solution", value:"Update to version 7.2.8, 7.3.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/PowerShell/Announcements/issues/35");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41076");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_powershell_core_detect_win.nasl");
  script_mandatory_keys("PowerShell/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers !~ "^7\.[23]")
  exit(99);

if(version_is_equal(version:vers, test_version:"7.3.0"))
  fix = "7.3.1";

else if(version_in_range_exclusive(version:vers, test_version_lo:"7.2", test_version_up:"7.2.8"))
  fix = "7.2.8";

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
