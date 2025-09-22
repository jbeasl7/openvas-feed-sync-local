# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:project";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834813");
  script_version("2024-12-12T09:30:20+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-11 15:03:12 +0530 (Wed, 11 Dec 2024)");
  script_name("Microsoft Project 2016 Defense in Depth Update (KB5002652)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5002652");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified
  vulnerability in Microsoft Project.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to bypass defense-in-depth measures.");

  script_tag(name:"affected", value:"Microsoft Project 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002652");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/ADV240002");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_project_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Microsoft/Project/Win/Ver");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
proPath = infos["location"];

if(!proPath || "Did not find install path from registry" >< proPath) {
  exit(0);
}

path = proPath + "\root\Office16";
vers = fetch_file_version(sysPath:path, file_name:"winproj.exe");
if(!vers) {
  exit(0);
}

if(version_in_range(version:vers, test_version:"16.0.4771.0", test_version2:"16.0.5478.9999")) {
  report = report_fixed_ver(file_checked:path + "\winproj.exe", file_version:vers, vulnerable_range:"16.0.4771.0 - 16.0.5478.9999");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
