# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812322");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2017-7843");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-06 16:35:00 +0000 (Mon, 06 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-12-05 12:30:09 +0530 (Tue, 05 Dec 2017)");
  script_name("Mozilla Firefox Security Bypass Vulnerability (MFSA2017-27) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the web worker in private
  browsing mode can write IndexedDB data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass security restrictions.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 57.0.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 57.0.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-27");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ffVer = infos["version"];
ffPath = infos["location"];

if(version_is_less(version:ffVer, test_version:"57.0.1"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"57.0.1", install_path:ffPath);
  security_message(data:report);
  exit(0);
}

exit(99);
