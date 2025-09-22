# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832878");
  script_version("2025-07-25T05:44:05+0000");
  script_cve_id("CVE-2024-23273", "CVE-2024-23254", "CVE-2024-23263", "CVE-2024-23280",
                "CVE-2024-23284", "CVE-2024-54658");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-03 17:29:15 +0000 (Mon, 03 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-03-22 11:44:58 +0530 (Fri, 22 Mar 2024)");
  script_name("Apple Safari Security Update (HT214089)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple
  vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-23273: Private Browsing tabs may be accessed without authentication

  - CVE-2024-23263: Processing maliciously crafted web content may prevent Content Security Policy from being enforced

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct arbitrary code execution and denial of service.");

  script_tag(name:"affected", value:"Apple Safari prior to version 17.4");

  script_tag(name:"solution", value:"Update to version 17.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214089");
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
if(!osVer || (osVer !~ "^12\." && osVer !~ "^13\.") || "Mac OS X" >!< osName)
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"17.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.4", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
