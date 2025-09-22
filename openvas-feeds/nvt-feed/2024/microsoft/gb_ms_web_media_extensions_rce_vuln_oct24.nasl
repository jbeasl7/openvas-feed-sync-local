# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:web_media_extensions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834529");
  script_version("2024-11-07T05:05:35+0000");
  script_cve_id("CVE-2021-28465");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-11-07 05:05:35 +0000 (Thu, 07 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-18 15:50:41 +0000 (Tue, 18 May 2021)");
  script_tag(name:"creation_date", value:"2024-10-22 13:19:37 +0530 (Tue, 22 Oct 2024)");
  script_name("Microsoft Web Media Extensions RCE Vulnerability (Oct 2024)");

  script_tag(name:"summary", value:"Microsoft Web Media Extensions is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a remote code
  execution vulnerability in Microsoft Web Media Extensions.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct remote code execution.");

  script_tag(name:"affected", value:"Microsoft Web Media Extensions prior to  1.0.40831.0.");

  script_tag(name:"solution", value:"Update to version 1.0.40831.0 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-28465");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_web_media_extensions_detect_win.nasl");
  script_mandatory_keys("WebMediaExtensions/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"1.0.40831.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.40831.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
