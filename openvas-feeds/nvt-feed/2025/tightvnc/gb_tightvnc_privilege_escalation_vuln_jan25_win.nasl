# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tightvnc:tightvnc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834913");
  script_version("2025-05-27T10:30:31+0000");
  script_cve_id("CVE-2023-27830");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-05-27 10:30:31 +0000 (Tue, 27 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-24 15:59:43 +0000 (Mon, 24 Apr 2023)");
  script_tag(name:"creation_date", value:"2025-01-27 20:48:09 +0530 (Mon, 27 Jan 2025)");
  script_name("TightVNC Privilege Escalation Vulnerability (Jan 2025) - Windows");

  script_tag(name:"summary", value:"TightVNC is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to TightVNC mishandling
  file permissions and trust during file transfer operations.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to escalate privileges on the host operating system via replacing legitimate
  files with crafted files when executing a file transfer.");

  script_tag(name:"affected", value:"TightVNC version prior to 2.8.75 on
  Windows.");

  script_tag(name:"solution", value:"Update to version 2.8.75 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://medium.com/nestedif/vulnerability-disclosure-privilege-escalation-tightvnc-8165208cce");
  script_xref(name:"URL", value:"https://www.tightvnc.com/whatsnew.php");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_tightvnc_detect_win.nasl");
  script_mandatory_keys("TightVNC/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"2.8.75")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.8.75", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
