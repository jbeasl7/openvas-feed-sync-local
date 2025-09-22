# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834694");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2024-21259", "CVE-2024-21263", "CVE-2024-21273", "CVE-2024-21248");
  script_tag(name:"cvss_base", value:"5.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:M/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 20:15:16 +0000 (Tue, 15 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-16 16:21:24 +0530 (Wed, 16 Oct 2024)");
  script_name("Oracle VirtualBox Security Update (oct24-1) - Windows");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the

  - CVE-2024-21259: An error in the Core component of Oracle VM VirtualBox.

  - CVE-2024-21263: An error in the Core component of Oracle VM VirtualBox.

  - CVE-2024-21273: An error in the Core component of Oracle VM VirtualBox.

  - CVE-2024-21248: An error in the Core component of Oracle VM VirtualBox.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute remote code, disclose information and cause denial of service
  attacks.");

  script_tag(name:"affected", value:"Oracle VirtualBox version 7.0.x prior
  to 7.0.22 and 7.1.x prior to 7.1.2 on Windows.");

  script_tag(name:"solution", value:"Update to version 7.0.22 or 7.1.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2024.html#AppendixOVIR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^7\.0\." && version_is_less(version:vers, test_version:"7.0.22")) {
  fix = "7.0.22";
}

if(vers =~ "^7\.1\." && version_is_less(version:vers, test_version:"7.1.2")) {
  fix = "7.1.2";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
