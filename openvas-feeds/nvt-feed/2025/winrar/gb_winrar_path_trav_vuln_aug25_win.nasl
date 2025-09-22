# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rarlab:winrar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118699");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-13 19:08:45 +0000 (Wed, 13 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-11 13:13:37 +0000 (Mon, 11 Aug 2025)");

  script_cve_id("CVE-2025-8088");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RARLAB WinRAR Path Traversal Vulnerability (Aug 2025) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_winrar_detect.nasl");
  script_mandatory_keys("WinRAR/Ver");

  script_tag(name:"summary", value:"RARLAB WinRAR is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"A malicious archive can trick WinRAR into placing an executable
  file in a sensitive system location, bypassing user-intended extraction paths.");

  script_tag(name:"impact", value:"Successful exploitation results in arbitrary code execution with
  the user's privileges, leading to a potential full system compromise.");

  script_tag(name:"affected", value:"RARLAB WinRAR prior to version 7.13 on Windows.");

  script_tag(name:"solution", value:"Update to version 7.13 or later.");

  script_xref(name:"URL", value:"https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5");
  script_xref(name:"URL", value:"https://thehackernews.com/2025/08/winrar-zero-day-under-active.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.13")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.13", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
