# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813047");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-5146");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-11 19:33:00 +0000 (Mon, 11 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-03-22 11:00:45 +0530 (Thu, 22 Mar 2018)");
  script_name("Mozilla Firefox ESR Security Advisories (MFSA2018-08, MFSA2018-08) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out of bounds
  memory write error in libvorbis library.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code within the context of the user running the affected
  application. Failed exploit attempts will likely cause denial-of-service
  conditions.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 52.7.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 52.7.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-08");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103432");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ffVer = infos["version"];
ffPath = infos["location"];

if(version_is_less(version:ffVer, test_version:"52.7.2"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"52.7.2", install_path:ffPath);
  security_message(data:report);
  exit(0);
}

exit(99);
