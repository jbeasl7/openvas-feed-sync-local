# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815103");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2019-2602", "CVE-2019-2684");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-06 17:54:00 +0000 (Thu, 06 Oct 2022)");
  script_tag(name:"creation_date", value:"2019-04-18 14:52:15 +0530 (Thu, 18 Apr 2019)");
  script_name("Oracle Java SE Security Updates (apr2019-5072813) 03 - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in 'Libraries' component of Java SE.

  - An error in 'RMI' component of Java SE.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attacker to have an impact on integrity and availability");

  script_tag(name:"affected", value:"Oracle Java SE version 7u211(1.7.0.211)
  and earlier, 8u202(1.8.0.202) and earlier, 11.0.2 and earlier and 12 on Windows.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html#AppendixJAVA");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:sun:jre");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.211")||
   version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.202")||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.2")||
   version_is_equal(version:vers, test_version:"12")) {
  report = report_fixed_ver(installed_version:vers, fixed_version: "Apply the patch", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
