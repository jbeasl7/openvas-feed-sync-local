# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807962");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"creation_date", value:"2016-05-04 17:26:15 +0530 (Wed, 04 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Squid Multiple Vulnerabilities (SQUID-2016:5, SQUID-2016:6) - Windows");

  script_tag(name:"summary", value:"Squid is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overflow in the cachemgr.cgi tool.

  - Multiple on-stack buffer overflow from incorrect bounds calculation in Squid ESI processing.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service, execute arbitrary code, or obtain sensitive stack layout information.");

  script_tag(name:"affected", value:"Squid version 3.x before 3.5.17 and 4.x
  before 4.0.9.");

  script_tag(name:"solution", value:"Update to version 3.5.17, 4.0.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1035647");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2016_6.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2016_5.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_squid_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("squid/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^[34]\.") {
  if(version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.5.16")) {
    fix = "3.5.17";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.0.8")) {
    fix = "4.0.9";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:vers, fixed_version:fix);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
