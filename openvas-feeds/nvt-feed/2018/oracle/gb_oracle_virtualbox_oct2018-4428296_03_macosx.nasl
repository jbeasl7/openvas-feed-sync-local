# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814266");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2018-3287", "CVE-2018-0732", "CVE-2018-2909", "CVE-2018-3290",
                "CVE-2018-3291", "CVE-2018-3292", "CVE-2018-3293", "CVE-2018-3294",
                "CVE-2018-3295", "CVE-2018-3296", "CVE-2018-3297", "CVE-2018-3298",
                "CVE-2018-3289", "CVE-2018-3288");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-10-17 12:26:38 +0530 (Wed, 17 Oct 2018)");
  script_name("Oracle VirtualBox Security Updates (oct2018-4428296) 03 - Mac OS X");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors within 'Core' component of Oracle VM VirtualBox.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to gain elevated privileges on  the host system and complete
  takeover of the Oracle VM VirtualBox.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions prior to 5.2.20 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 5.2.20 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html#AppendixOVIR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

if(vers =~ "^5\.2") {
  if(version_is_less(version:vers, test_version:"5.2.20")) {
    report = report_fixed_ver(installed_version:vers, fixed_version: "5.2.20", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
