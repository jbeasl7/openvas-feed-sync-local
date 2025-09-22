# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832947");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2024-21112", "CVE-2024-21113", "CVE-2024-21114", "CVE-2024-21115",
                "CVE-2024-21103", "CVE-2024-21111", "CVE-2024-21116", "CVE-2024-21110",
                "CVE-2024-21107", "CVE-2024-21106", "CVE-2024-21121", "CVE-2024-21109",
                "CVE-2024-21108");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-16 22:15:33 +0000 (Tue, 16 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-18 12:52:01 +0530 (Thu, 18 Apr 2024)");
  script_name("Oracle VirtualBox Security Update (apr2024) - Windows");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-21112: Privilege escalation

  - CVE-2024-21113: Privilege escalation

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code and to gain escalated privileges.");

  script_tag(name:"affected", value:"Oracle VirtualBox version 7.0.x prior
  to 7.0.16 on Windows.");

  script_tag(name:"solution", value:"Update to version 7.0.16 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2024.html#AppendixOVIR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^7\.0\." && version_is_less(version:vers, test_version:"7.0.16")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.0.16", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
