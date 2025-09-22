# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810604");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2017-3302");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-02-16 15:03:30 +0530 (Thu, 16 Feb 2017)");
  script_name("Oracle MySQL Denial Of Service Vulnerability (Feb 2017) - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exist as,

  - In sql-common/client.c script 'mysql_prune_stmt_list' function, the for loop
    adds elements to pruned_list without removing it from the existing list.

  - If application gets disconnected just before it tries to prepare a new
    statement, 'mysql_prune_stmt_list' tries to detach all previously prepared
    statements.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow attackers to cause crash of applications using that MySQL client.");

  script_tag(name:"affected", value:"Oracle MySQL version before 5.6.21 and
  5.7.x before 5.7.5 on Linux");

  script_tag(name:"solution", value:"Upgrade to Oracle MySQL version 5.6.21 or
  5.7.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://bugs.mysql.com/bug.php?id=63363");
  script_xref(name:"URL", value:"https://bugs.mysql.com/bug.php?id=70429");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/02/11/11");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(vers =~ "^5\.7\.")
{
  if(version_is_less(version:vers, test_version:"5.7.5"))
  {
    VULN = TRUE;
    fix = "5.7.5";
  }
}

else if(version_is_less(version:vers, test_version:"5.6.21"))
{
  VULN = TRUE;
  fix = "5.6.21";
}

if(VULN)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
