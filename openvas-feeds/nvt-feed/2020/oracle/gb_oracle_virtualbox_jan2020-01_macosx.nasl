# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816610");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2020-2674", "CVE-2020-2682", "CVE-2020-2698", "CVE-2020-2701",
                "CVE-2020-2702", "CVE-2020-2726", "CVE-2020-2681", "CVE-2020-2689",
                "CVE-2020-2690", "CVE-2020-2691", "CVE-2020-2692", "CVE-2020-2704",
                "CVE-2020-2705", "CVE-2020-2725", "CVE-2020-2678", "CVE-2020-2727",
                "CVE-2020-2693");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-25 19:18:00 +0000 (Thu, 25 Feb 2021)");
  script_tag(name:"creation_date", value:"2020-01-16 15:48:28 +0530 (Thu, 16 Jan 2020)");
  script_name("Oracle VirtualBox Security Update (cpujan2020 - 01) - Mac OS X");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple errors
  in 'Core' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions prior to 5.2.36, 6.1.x
  prior to 6.1.2 and 6.0.x prior to 6.0.16.");

  script_tag(name:"solution", value:"Update to Oracle VirtualBox version 5.2.36
  or 6.0.16 or 6.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2020.html#AppendixOVIR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
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

if(vers =~ "^6\.0\." && version_is_less(version:vers, test_version:"6.0.16")) {
  fix = "6.0.16";
}
else if(vers =~ "^6\.1\." && version_is_less(version:vers, test_version:"6.1.2")) {
  fix = "6.1.2";
}
else if(version_is_less(version:vers, test_version:"5.2.36")) {
  fix = "5.2.36";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
