# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834618");
  script_version("2025-07-25T05:44:05+0000");
  script_cve_id("CVE-2024-40866", "CVE-2024-44187", "CVE-2024-40857", "CVE-2024-44202",
                "CVE-2024-44155", "CVE-2024-44192", "CVE-2024-54467");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-25 13:25:52 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-20 10:38:11 +0530 (Fri, 20 Sep 2024)");
  script_name("Apple Safari Security Update (HT121241)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple
  vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name: "insight" , value:"These vulnerabilities exist:

  - CVE-2024-40866: The issue was addressed with improved UI

  - CVE-2024-44187: A cross-origin issue existed with 'iframe' elements

  - CVE-2024-40857: This issue was addressed through improved state management");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to execute arbitrary code and conduct spoofing attacks.");

  script_tag(name: "affected" , value:"Apple Safari prior to version 18");

  script_tag(name: "solution" , value:"Update to version 18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/121241");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || (osVer !~ "^13\." && osVer !~ "^14\.") || "Mac OS X" >!< osName)
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"18")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"18", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
