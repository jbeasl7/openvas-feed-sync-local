# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820088");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2022-21491", "CVE-2022-21465", "CVE-2022-21471", "CVE-2022-21487",
                "CVE-2022-21488");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-28 14:40:00 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-20 17:41:27 +0530 (Wed, 20 Apr 2022)");
  script_name("Oracle VirtualBox Security Update (cpuapr2022) - Mac OS X");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple unspecified
  errors in 'Core' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  have an impact on confidentiality.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions 6.1.x prior to 6.1.34
  on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 6.1.34
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2022.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_oracle_virtualbox_detect_macosx.nasl");
  script_mandatory_keys("Oracle/VirtualBox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^6\.1\." && version_is_less(version:vers, test_version:"6.1.34")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.1.34", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
