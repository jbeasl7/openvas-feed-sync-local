# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:raw_image_extension";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836388");
  script_version("2025-06-06T05:41:39+0000");
  script_cve_id("CVE-2022-23300", "CVE-2022-23295");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-06-06 05:41:39 +0000 (Fri, 06 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-14 18:22:27 +0000 (Mon, 14 Mar 2022)");
  script_tag(name:"creation_date", value:"2025-05-30 16:26:12 +0530 (Fri, 30 May 2025)");
  script_name("Microsoft Raw Image Extension Multiple Vulnerabilities (May 2025) - Windows");

  script_tag(name:"summary", value:"Microsoft Raw Image Extension is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution.");

  script_tag(name:"affected", value:"Microsoft Raw Image Extension prior to version 2.0.30391.0 on Microsoft Windows 10 and prior to version 2.1.30391.0 on Microsoft Windows 11.");

  script_tag(name:"solution", value:"Update to version 2.0.30391.0 or 2.1.30391.0 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-23300");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-23295");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_require_ports(139, 445);
  script_dependencies("gb_ms_raw_image_extension_detect_win.nasl");
  script_mandatory_keys("MSRawImageExtension/Win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win11:1, win10:1, win10x64:1) <= 0) {
  exit(0);
}

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)) {
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build) {
  exit(0);
}

version = infos["version"];
location = infos["location"];

if("19042" >< build || "19043" >< build || "19044" >< build || "14393" >< build || "17763" >< build || "18363" >< build) {
  if(version_is_less(version:version, test_version:"2.0.30391.0")) {
    fix = "2.0.30391.0";
  }
}

if("22000" >< build) {
  if(version_is_less(version:version, test_version:"2.1.30391.0")) {
    fix = "2.1.30391.0";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);