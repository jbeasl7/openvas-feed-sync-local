# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107018");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2015-4913", "CVE-2015-4830", "CVE-2015-4826", "CVE-2015-4815",
                "CVE-2015-4807", "CVE-2015-4802", "CVE-2015-4792", "CVE-2015-4870",
                "CVE-2015-4861", "CVE-2015-4858", "CVE-2015-4836");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-07-01 12:46:24 +0530 (Fri, 01 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle MySQL Multiple Unspecified Vulnerabilities-01 (Oct 2015) - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors exist in the MySQL Server
  component via unknown vectors related to Server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated remote attacker to affect confidentiality, integrity, and
  availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.5.45 and earlier
  and 5.6.26 and earlier on windows");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77153");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77228");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77237");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77222");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77205");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77165");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77171");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77208");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77137");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77145");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77190");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:oracle:mysql";

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^5\.[56]\.")
{
  if(version_in_range(version:vers, test_version:"5.5", test_version2:"5.5.45") ||
     version_in_range(version:vers, test_version:"5.6", test_version2:"5.6.26"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the patch", install_path:path);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
