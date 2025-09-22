# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:git_for_windows_project:git_for_windows";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811706");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-1000117");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-08-17 11:01:31 +0530 (Thu, 17 Aug 2017)");
  script_name("Git Remote Code Execution Vulnerability - Windows");

  script_tag(name:"summary", value:"Git is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error related to the
  handling of 'ssh' URLs.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code on the
  affected system.");

  script_tag(name:"affected", value:"Git versions 2.14.x prior to 2.14.1, 2.13.x
  prior to 2.13.5, 2.12.x prior to 2.12.4, 2.11.x prior to 2.11.3, 2.10.x prior to
  2.10.4, 2.9.x prior to 2.9.5, 2.8.x prior to 2.8.6 and 2.7.x prior to 2.7.6.");

  script_tag(name:"solution", value:"Upgrade to Git version 2.14.1 or 2.13.5 or
  2.12.4 or 2.11.3 or 2.10.4 or 2.9.5 or 2.8.6 or 2.7.6 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.esecurityplanet.com/threats/git-svn-and-mercurial-open-source-version-control-systems-update-for-critical-security-vulnerability.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100283");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_git_detect_win.nasl");
  script_mandatory_keys("Git/Win/Ver");
  script_xref(name:"URL", value:"https://git-scm.com/download/win");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!git_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(git_ver =~ "^(2\.14\.)" && version_is_less(version:git_ver, test_version:"2.14.1")){
  fix = "2.14.1";
}
else if(git_ver =~ "^(2\.13\.)" && version_is_less(version:git_ver, test_version:"2.13.5")){
  fix = "2.13.5";
}
else if(git_ver =~ "^(2\.12\.)" && version_is_less(version:git_ver, test_version:"2.12.4")){
  fix = "2.12.4";
}
else if(git_ver =~ "^(2\.11\.)" && version_is_less(version:git_ver, test_version:"2.11.3")){
  fix = "2.11.3";
}
else if(git_ver =~ "^(2\.10\.)" && version_is_less(version:git_ver, test_version:"2.10.4")){
  fix = "2.10.4";
}
else if(git_ver =~ "^(2\.9\.)" && version_is_less(version:git_ver, test_version:"2.9.5")){
  fix = "2.9.5";
}
else if(git_ver =~ "^(2\.8\.)" && version_is_less(version:git_ver, test_version:"2.8.6")){
  fix = "2.8.6";
}
else if(git_ver =~ "^(2\.7\.)" && version_is_less(version:git_ver, test_version:"2.7.6")){
  fix = "2.7.6";
}

if(fix)
{
  report = report_fixed_ver(installed_version:git_ver, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
