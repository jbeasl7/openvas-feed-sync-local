# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834642");
  script_version("2025-01-09T06:16:22+0000");
  script_cve_id("CVE-2024-9392", "CVE-2024-9393", "CVE-2024-9394", "CVE-2024-9396",
                "CVE-2024-9397", "CVE-2024-9398", "CVE-2024-9399", "CVE-2024-9400",
                "CVE-2024-9401", "CVE-2024-9402", "CVE-2024-9403");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 16:04:59 +0000 (Tue, 15 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-03 11:24:34 +0530 (Thu, 03 Oct 2024)");
  script_name("Mozilla Thunderbird Security Update (MFSA2024-50) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name: "insight" , value:"These vulnerabilities exist:

  - CVE-2024-9396: Potential memory corruption may occur when cloning certain objects

  - CVE-2024-9398: External protocol handlers could be enumerated via popups");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information, bypass security restrictions and
  conduct denial of service attacks.");

  script_tag(name: "affected" , value:"Mozilla Thunderbird prior to version
  131 on Windows.");

  script_tag(name: "solution" , value:"Update to version 131 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-50/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"131")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"131", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
