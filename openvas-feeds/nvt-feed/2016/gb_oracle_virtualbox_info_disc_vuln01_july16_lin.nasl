# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808262");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2016-3612");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-07-21 12:24:33 +0530 (Thu, 21 Jul 2016)");
  script_name("Oracle VirtualBox Information Disclosure Vulnerability-01 (Jul 2016) - Linux");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified
  error in an unknown function of the component SSL/TLS.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on confidentiality.");

  script_tag(name:"affected", value:"Oracle VirtualBox versions prior to 5.0.22
  on Linux.");

  script_tag(name:"solution", value:"Update to version 5.0.22 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91860");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^5\.0\.") {
  if(version_in_range(version:vers, test_version:"5.0.0", test_version2:"5.0.21")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"5.0.22", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
