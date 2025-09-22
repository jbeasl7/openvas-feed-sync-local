# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836080");
  script_version("2025-07-25T05:44:05+0000");
  script_cve_id("CVE-2025-24180", "CVE-2025-24113", "CVE-2025-30467", "CVE-2025-31192",
                "CVE-2025-24167", "CVE-2025-31184", "CVE-2025-24192", "CVE-2025-24264",
                "CVE-2025-24216", "CVE-2025-24213", "CVE-2025-24209", "CVE-2025-24208",
                "CVE-2025-30427", "CVE-2025-30425", "CVE-2025-30466");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-30 19:10:53 +0000 (Thu, 30 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-04-01 11:04:56 +0530 (Tue, 01 Apr 2025)");
  script_name("Apple Safari Security Update (HT122379)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple
  vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to bypass browser extension authentication, run arbitrary code, disclose
  information and conduct spoofing and denial of service attacks.");

  script_tag(name: "affected" , value:"Apple Safari prior to version 18.4");

  script_tag(name: "solution" , value:"Update to version 18.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/122379");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"18.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"18.4", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
