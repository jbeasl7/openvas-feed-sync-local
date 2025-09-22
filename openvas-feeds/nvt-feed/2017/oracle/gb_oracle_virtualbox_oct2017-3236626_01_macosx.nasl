# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811982");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2017-10407", "CVE-2017-3733", "CVE-2017-10428", "CVE-2017-10392",
                "CVE-2017-10408");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-23 19:30:00 +0000 (Tue, 23 Apr 2019)");
  script_tag(name:"creation_date", value:"2017-10-18 12:48:50 +0530 (Wed, 18 Oct 2017)");
  script_name("Oracle VirtualBox Security Updates (oct2017-3236626) 01 - Mac OS X");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors in 'core' component.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to compromise availability
  confidentiality and integrity of the system.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions prior to 5.1.30 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 5.1.30 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101370");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96269");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101362");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101368");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101371");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"5.1.30")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.1.30", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
