# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:notepad-plus-plus:notepad++";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826490");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2022-32168");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-29 16:22:00 +0000 (Thu, 29 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-30 12:15:00 +0530 (Fri, 30 Sep 2022)");
  script_name("Notepad++ DLL hijacking Vulnerability (Sep 2022)");

  script_tag(name:"summary", value:"Notepad++ is prone to a DLL hijacking
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to dll hijacking
  vulnerability in UxTheme.dll.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Notepad++ version 8.3 through 8.4.4
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Notepad++ version 8.4.5 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/notepad-plus-plus/notepad-plus-plus/commit/85d7215d9b3e0d5a8433fc31aec4f2966821051e");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_notepadpp_detect_portable_win.nasl");
  script_mandatory_keys("Notepad++64/Win/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"8.3", test_version2:"8.4.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.4.5", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
