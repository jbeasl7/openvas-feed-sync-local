# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812642");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2018-2688", "CVE-2018-2689", "CVE-2018-2676", "CVE-2018-2698",
                "CVE-2018-2694", "CVE-2018-2693", "CVE-2018-2685", "CVE-2018-2686",
                "CVE-2018-2687", "CVE-2018-2690", "CVE-2017-5715", "CVE-2017-3735");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2018-01-17 13:17:18 +0530 (Wed, 17 Jan 2018)");
  script_name("Oracle VirtualBox Security Updates (jan2018-3236628) - Linux");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Multiple errors in the 'Core' component of the application.

  - An error in the 'Guest Additions' component of the application.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow local attackers to gain elevated privileges on
  the host system.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions prior to 5.1.32 and 5.2.x prior to
  5.2.6 on Linux.");

  script_tag(name:"solution", value:"Update to version 5.1.32, 5.2.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^5\.2" && (version_is_less(version:vers, test_version:"5.2.6"))) {
  fix = "5.2.6";
}

else if(version_is_less(version:vers, test_version:"5.1.32")) {
  fix = "5.1.32";
}

if(fix){
  report = report_fixed_ver(installed_version:vers, fixed_version: fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
