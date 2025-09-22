# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813146");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2018-2846", "CVE-2018-2776", "CVE-2018-2762", "CVE-2018-2816",
                "CVE-2018-2769", "CVE-2018-2780", "CVE-2018-2786", "CVE-2018-2839",
                "CVE-2018-2778", "CVE-2018-2779", "CVE-2018-2775", "CVE-2018-2777",
                "CVE-2018-2810", "CVE-2018-2812", "CVE-2018-2759");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-04-19 10:34:42 +0530 (Thu, 19 Apr 2018)");
  script_name("Oracle Mysql Security Updates (apr2018-3678067) 03 - Windows");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - An error in the 'Server:Performance Schema' component of MySQL Server.

  - An error in the 'Group Replication GCS' component of MySQL Server.

  - An error in the 'Server:Connection' component of MySQL Server.

  - Multiple errors in the 'Server:Optimizer' component of MySQL Server.

  - An error in the 'Server:Pluggable Auth' component of MySQL Server.

  - An error in the 'Server:DML' component of MySQL Server.

  - Multiple errors in the 'InnoDB' component of MySQL Server.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote to conduct a denial of service and have an
  impact on integrity.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.7.21 and earlier
  on Windows");

  script_tag(name:"solution", value:"Apply the latest patch from vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

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

if(version_in_range(version:version, test_version:"5.7", test_version2:"5.7.21")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"Apply the patch", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
