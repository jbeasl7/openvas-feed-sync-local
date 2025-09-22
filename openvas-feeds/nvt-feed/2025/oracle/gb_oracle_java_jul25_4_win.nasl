# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836520");
  script_version("2025-07-18T15:43:33+0000");
  script_cve_id("CVE-2025-27113", "CVE-2025-24855", "CVE-2024-55549", "CVE-2024-40896",
                "CVE-2024-56171", "CVE-2025-24928", "CVE-2025-32414", "CVE-2025-32415");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-07-18 15:43:33 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-23 18:17:52 +0000 (Wed, 23 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-07-16 15:04:46 +0530 (Wed, 16 Jul 2025)");
  script_name("Oracle Java SE <= 8u451-b50 Security Update (Jul 2025) - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to take control of Oracle Java SE.");

  script_tag(name:"affected", value:"Oracle Java SE version 8u451-b50 and prior
  on Windows.");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2025.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
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

# Java SE 8u451-b50 is a more specific build within the 8u451 release. Therefore, Java SE 8u451 is the greater version because it encompasses all builds within that update, including 8u451-b50
# Currently, we are not detecting build numbers, so the version ranges have been reduced to 1.
if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.450")) {
  report = report_fixed_ver(installed_version:vers, fixed_version: "Apply patch provided by the vendor", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
