# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813633");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2018-4279", "CVE-2018-4270", "CVE-2018-4278", "CVE-2018-4284",
                "CVE-2018-4266", "CVE-2018-4261", "CVE-2018-4262", "CVE-2018-4263",
                "CVE-2018-4264", "CVE-2018-4265", "CVE-2018-4267", "CVE-2018-4272",
                "CVE-2018-4271", "CVE-2018-4273", "CVE-2018-4274", "CVE-2018-4260");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-04 19:35:00 +0000 (Thu, 04 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-07-10 09:47:26 +0530 (Tue, 10 Jul 2018)");
  script_name("Apple Safari Security Updates (HT208934)");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An inconsistent user interface issue.

  - Sound fetched through audio elements may be exfiltrated cross-origin.

  - A type confusion issue due to poor memory handling.

  - A race condition issue due to improper validation.

  - Multiple memory corruption issues due to poor memory handling and improper
    input validation.

  - A spoofing issue existed in the handling of URLs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct address bar spoofing, arbitrary code execution and
  cause a denial of service condition.");

  script_tag(name:"affected", value:"Apple Safari versions before 11.1.2.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 11.1.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208934");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"11.1.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.1.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
