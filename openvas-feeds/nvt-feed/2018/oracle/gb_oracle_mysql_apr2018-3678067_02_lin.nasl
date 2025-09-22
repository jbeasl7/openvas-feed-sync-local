# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813145");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2018-2766", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2787",
                "CVE-2018-2758");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-01 15:00:00 +0000 (Mon, 01 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-04-19 10:32:41 +0530 (Thu, 19 Apr 2018)");
  script_name("Oracle Mysql Security Updates (apr2018-3678067) 02 - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Multiple errors in 'InnoDB' component of the MySQL Server.

  - An error in the 'Server:Security:Privileges' component of the MySQL Server.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to conduct a denial of service
  condition and have an impact on integrity.");

  script_tag(name:"affected", value:"Oracle MySQL versions 5.6.39 and earlier,
  5.7.21 and earlier on Linux");

  script_tag(name:"solution", value:"Apply the latest patch from vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version_in_range(version:version, test_version:"5.6", test_version2:"5.6.39") ||
   version_in_range(version:version, test_version:"5.7", test_version2:"5.7.21")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"Apply the patch", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
