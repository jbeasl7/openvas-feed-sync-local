# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:bridge_cc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832871");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2024-20752", "CVE-2024-20755", "CVE-2024-20756", "CVE-2024-20757");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-18 16:15:07 +0000 (Mon, 18 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-14 16:10:00 +0530 (Thu, 14 Mar 2024)");
  script_name("Adobe Bridge Multiple Vulnerabilities (APSB24-15) - Windows");

  script_tag(name:"summary", value:"The Adobe Bridge device is missing a
  security update announced via the apsb24-15 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-20752: Arbitrary code execution

  - CVE-2024-20757: Memory leak

  - Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct memory leak attack and execute arbitrary code.");

  script_tag(name:"affected", value:"Adobe Bridge 13.0.5 and earlier versions,
  14.0.1 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Update to version 13.0.6 or 14.0.2 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb24-15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_bridge_cc_detect.nasl");
  script_mandatory_keys("Adobe/Bridge/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_in_range_exclusive(version:vers, test_version_lo:"14.0", test_version_up:"14.0.2")) {
  fix = "14.0.2 or later";
}
else if(version_in_range_exclusive(version:vers, test_version_lo:"13.0", test_version_up:"13.0.6")) {
  fix = "13.0.6 or later";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
