# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:vp9_video_extensions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836369");
  script_version("2025-06-02T05:40:56+0000");
  script_cve_id("CVE-2021-31967");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-06-02 05:40:56 +0000 (Mon, 02 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 16:50:49 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"creation_date", value:"2025-05-27 10:52:21 +0530 (Tue, 27 May 2025)");
  script_name("Microsoft VP9 Video Extensions RCE Vulnerability (May 2025) - Windows");

  script_tag(name:"summary", value:"Microsoft VP9 Video Extensions is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution.");

  script_tag(name:"affected", value:"Microsoft VP9 Video Extensions prior to version 1.0.41182.0 on Microsoft Windows.");

  script_tag(name:"solution", value:"Update to version 1.0.41182.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31967");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");

  script_dependencies("gb_ms_vp9_video_extensions_detect_win.nasl");
  script_mandatory_keys("MSVP9Extension/Win/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"1.0.41182.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.41182.0", install_path: location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
