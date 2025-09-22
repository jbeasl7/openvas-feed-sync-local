# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xnview:xnview";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813820");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-15175", "CVE-2018-15176", "CVE-2018-15174");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-04 18:06:00 +0000 (Thu, 04 Oct 2018)");
  script_tag(name:"creation_date", value:"2018-08-10 10:11:02 +0530 (Fri, 10 Aug 2018)");

  script_name("XnView Multiple Denial of Service Vulnerabilities (Aug 2018)");

  script_tag(name:"summary", value:"XnView is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple improper input validation errors related to the component 'rle File Handler'.

  - An improper input validation related to an unknown function of the component 'ICO File Handler'.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial of service or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"XnView Version 0.90 and probably prior.");

  script_tag(name:"solution", value:"Update to version 0.91 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://code610.blogspot.com/2018/08/updating-xnview.html");
  script_xref(name:"URL", value:"https://www.xnview.com/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
xnVer = infos["version"];
xnPath = infos["location"];

if(version_is_less(version: xnVer, test_version: "0.91")) {
  report = report_fixed_ver(installed_version:xnVer, fixed_version:"0.91", install_path:xnPath);
  security_message(data:report);
  exit(0);
}

exit(0);
