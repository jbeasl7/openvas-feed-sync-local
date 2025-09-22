# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:java_sdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813819");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-1417");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-08-09 14:03:02 +0530 (Thu, 09 Aug 2018)");
  script_name("IBM Java SDK Remote Privilege Escalation Vulnerability - Linux");

  script_tag(name:"summary", value:"IBM Java SDK is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified flaw
  in the J9 JVM.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to gain elevated privileges on an affected system.");

  script_tag(name:"affected", value:"IBM SDK, Java Technology Edition 7.1 before
  7.1.4.20 and 8.0 before 8.0.5.10.");

  script_tag(name:"solution", value:"Upgrade to IBM Java SDK 7.1.4.20 or 8.0.5.10
  or later. Please see the references for more information.");

  script_xref(name:"URL", value:"https://www.securitytracker.com/id/1040403");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103216");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04021");
  script_xref(name:"URL", value:"https://www.ibm.com/developerworks/java/jdk");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("IBM/Java/SDK/Linux/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
javaVer = infos["version"];
javaPath = infos["location"];

if(javaVer =~ "^7\.1" && version_is_less(version:javaVer, test_version:"7.1.4.20")){
  fix = "7.1.4.20";
}
else if(javaVer =~ "^8\.0" && version_is_less(version:javaVer, test_version:"8.0.5.10")){
  fix = "8.0.5.10";
}

if(fix)
{
  report = report_fixed_ver(installed_version:javaVer, fixed_version:fix, install_path:javaPath);
  security_message(data:report);
  exit(0);
}
