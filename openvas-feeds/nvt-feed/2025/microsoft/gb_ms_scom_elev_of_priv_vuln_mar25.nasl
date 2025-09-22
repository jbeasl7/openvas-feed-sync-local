# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:system_center_operations_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836010");
  script_version("2025-03-12T05:38:19+0000");
  script_cve_id("CVE-2024-43594");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-12 05:38:19 +0000 (Wed, 12 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-12 02:00:54 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"creation_date", value:"2025-03-11 17:23:22 +0530 (Tue, 11 Mar 2025)");
  script_name("Microsoft System Center Operations Manager Elevation of Privilege Vulnerability (2748552)");

  script_tag(name:"summary", value:"Microsoft System Center Operations Manager
  is prone to an elevation of privilege vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an elevation of
  privilege vulnerability exists in SOCM");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges.");

  script_tag(name:"affected", value:"- Microsoft System Center Operations Manager 2019

  - Microsoft System Center Operations Manager 2022

  - Microsoft System Center Operations Manager 2025");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43594");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_scom_detect_win.nasl");
  script_mandatory_keys("MS/SCOM/Ver", "MS/SCOM/Path");
  script_require_ports(139, 445);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

scom_name = get_kb_item("MS/SCOM/Ver");

if(!scom_name)
  exit(0);

if("System Center Operations Manager 2019" >< scom_name || "System Center Operations Manager 2022" >< scom_name || "System Center Operations Manager 2025" >< scom_name) {
  path = get_kb_item("MS/SCOM/Path");
  if(path && "Could not find the install Location" >!< path) {
    vers = fetch_file_version(sysPath: path, file_name:"Microsoft.Mom.ConfigServiceHost.exe");
    if(vers) {
      if(version_in_range_exclusive(version: vers, test_version_lo: "10.25", test_version_up: "10.25.10132.0")) {
        fix = "10.25.10132.0";
      }
      if(version_in_range_exclusive(version: vers, test_version_lo: "10.22", test_version_up: "10.22.10684.0")) {
        fix = "10.22.10684.0";
      }
      if(version_in_range_exclusive(version: vers, test_version_lo: "10.19", test_version_up: "10.19.10652.0")) {
        fix = "10.19.10652.0";
      }
      if(fix) {
        report = report_fixed_ver(installed_version:vers, fixed_version:scom_name + " " + fix, install_path:path);
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

exit(99);