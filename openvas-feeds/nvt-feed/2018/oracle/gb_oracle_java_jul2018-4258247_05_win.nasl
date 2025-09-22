# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813688");
  script_version("2025-09-17T05:39:26+0000");
  script_cve_id("CVE-2018-2941");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-12 18:04:00 +0000 (Fri, 12 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-07-18 11:26:47 +0530 (Wed, 18 Jul 2018)");
  script_name("Oracle Java SE Security Updates-05 (jul2018-4258247) - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error
  in the JavaFX component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges.");

  script_tag(name:"affected", value:"Oracle Java SE version 10.0 through 10.0.1 and
  1.8.0.172 and earlier, 1.7.0.181 and earlier on Windows");

  script_tag(name:"solution", value:"Apply the appropriate patch from the vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html");
  script_xref(name:"URL", value:"https://securitytracker.com/id/1041302");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^(1\.[78]|10)") {
  if((version_in_range(version:vers, test_version:"10.0", test_version2:"10.0.1")) ||
     (version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.172")) ||
     (version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.181"))) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the patch", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
