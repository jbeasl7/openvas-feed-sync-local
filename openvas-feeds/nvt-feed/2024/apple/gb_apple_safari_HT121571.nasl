# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834766");
  script_version("2025-07-25T05:44:05+0000");
  script_cve_id("CVE-2024-44259", "CVE-2024-44229", "CVE-2024-44296", "CVE-2024-44244",
                "CVE-2024-44212");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-11 18:29:11 +0000 (Wed, 11 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-11-20 11:26:30 +0530 (Wed, 20 Nov 2024)");
  script_name("Apple Safari Security Update (HT121571)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple
  vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name: "insight" , value:"These vulnerabilities exist:

  - CVE-2024-44259: This issue was addressed through improved state management.

  - CVE-2024-44229: An information leakage was addressed with additional validation.

  - CVE-2024-44296: The issue was addressed with improved checks.

  - CVE-2024-44244: A memory corruption issue was addressed with improved input validation.

  - CVE-2024-44212: A cookie management issue was addressed with improved state management.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to execute arbitrary code, disclose information and conduct denial of service
  attacks.");

  script_tag(name: "affected" , value:"Apple Safari prior to version 18.1");

  script_tag(name: "solution" , value:"Update to version 18.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/121571");
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

if(version_is_less(version:vers, test_version:"18.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"18.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
