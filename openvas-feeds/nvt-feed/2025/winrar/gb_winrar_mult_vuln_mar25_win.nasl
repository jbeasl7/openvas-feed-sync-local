# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rarlab:winrar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834287");
  script_version("2025-03-14T05:38:04+0000");
  script_cve_id("CVE-2024-30370", "CVE-2024-36052");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-14 05:38:04 +0000 (Fri, 14 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-13 14:21:20 +0530 (Thu, 13 Mar 2025)");
  script_name("RARLabs WinRAR Multiple Vulnerabilities (Mar 2025) - Windows");

  script_tag(name:"summary", value:"WinRAR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-30370: An error in the archive extraction functionality.

  - CVE-2024-36052: A spoofing vulnerability in WinRAR.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to spoof the screen output via ANSI escape sequences, bypass the
  Mark-Of-The-Web protection mechanism and potentially compromise the affected
  system.");

  script_tag(name:"affected", value:"RARLabs WinRAR before 7.00 on Windows.");

  script_tag(name:"solution", value:"Update to version 7.00 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.rarlab.com/rarnew.htm");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-24-357/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_winrar_detect.nasl");
  script_mandatory_keys("WinRAR/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.00")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.00", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
