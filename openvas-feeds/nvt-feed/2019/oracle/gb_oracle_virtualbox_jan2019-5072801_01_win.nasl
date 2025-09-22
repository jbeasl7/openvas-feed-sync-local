# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814652");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2018-3309");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-01-16 15:28:01 +0530 (Wed, 16 Jan 2019)");
  script_name("Oracle VirtualBox Security Updates (jan2019-5072801) 01 - Windows");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to an unspecified security vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified
  error in Core component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to affect confidentiality, availability and integrity via
  unknown vectors.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions prior to 5.2.22 on Windows.");

  script_tag(name:"solution", value:"Update to version 5.2.22 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"5.2.22")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.2.22", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
