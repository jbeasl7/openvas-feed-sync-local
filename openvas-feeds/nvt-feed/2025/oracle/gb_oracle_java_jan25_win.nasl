# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834903");
  script_version("2025-01-24T05:37:33+0000");
  script_cve_id("CVE-2025-21502");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-24 05:37:33 +0000 (Fri, 24 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-21 21:15:15 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-22 11:17:43 +0530 (Wed, 22 Jan 2025)");
  script_name("Oracle Java SE Security Update (Jan 2025) - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to an unspecified
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  Hotspot component of Oracle Java SE.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform limited unauthorized modifications to data and disclose
  information.");

  script_tag(name:"affected", value:"Oracle Java SE version 17.0.x through
  17.0.13, 11.0.x through 11.0.25, 21.0.x through 21.0.5 and 23.0.x through
  23.0.1 on Windows.");

  script_tag(name:"solution", value:"The vendor has released updates. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2025.html");
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

if(version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.25") ||
   version_in_range(version:vers, test_version:"17.0", test_version2:"17.0.13") ||
   version_in_range(version:vers, test_version:"21.0", test_version2:"21.0.5") ||
   version_in_range(version:vers, test_version:"23.0", test_version2:"23.0.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version: "Apply patch provided by the vendor", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(0);