# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832045");
  script_version("2023-10-13T05:06:10+0000");
  script_cve_id("CVE-2023-21930", "CVE-2023-21937", "CVE-2023-21938", "CVE-2023-21939",
                "CVE-2023-21967", "CVE-2023-21968");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-18 20:37:00 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-19 16:13:26 +0530 (Wed, 19 Apr 2023)");
  script_name("Oracle Java SE Security Update (apr2023) 01 - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  errors in the networking components.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to manipulate data and execute arbitrary code.");

  script_tag(name:"affected", value:"Oracle Java SE version 8u361 and earlier,
  11.0.18, 17.0.6, 20.0.0 and earlier on Windows.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2023.html#AppendixJAVA");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:oracle:jre";

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.361") ||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.18") ||
   version_in_range(version:vers, test_version:"17.0", test_version2:"17.0.6") ||
   version_in_range(version:vers, test_version:"20.0", test_version2:"20.0.0"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version: "Apply patch from vendor", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
