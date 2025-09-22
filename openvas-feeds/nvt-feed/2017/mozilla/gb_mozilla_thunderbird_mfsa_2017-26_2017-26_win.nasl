# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812403");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2017-7828", "CVE-2017-7830", "CVE-2017-7826");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 12:06:00 +0000 (Wed, 01 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-12-07 11:21:23 +0530 (Thu, 07 Dec 2017)");
  script_name("Mozilla Thunderbird Security Advisories (MFSA2017-26, MFSA2017-26) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use-after-free of 'PressShell' while restyling layout.

  - Cross-origin URL information leak through Resource Timing API.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to impact confidentiality, integrity and availability of the system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 52.5 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 52.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-26/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
tbVer = infos["version"];
tbPath = infos["location"];

if(version_is_less(version:tbVer, test_version:"52.5"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"52.5", install_path:tbPath);
  security_message(data:report);
  exit(0);
}
