# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812196");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2013-3811", "CVE-2013-3806", "CVE-2013-3810", "CVE-2013-3807",
                "CVE-2013-3798", "CVE-2013-3796", "CVE-2013-3795");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-11-22 16:08:31 +0530 (Wed, 22 Nov 2017)");
  script_name("MySQL Unspecified vulnerabilities-05 (Jul 2013) - Linux");

  script_tag(name:"summary", value:"MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server
  component via unknown vectors related to InnoDB, XA Transactions, Server
  Privileges, MemCached, Server Optimizer and Data Manipulation Language.");

  script_tag(name:"affected", value:"Oracle MySQL 5.6.11 and earlier on Linux");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to affect availability via unknown vectors.");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61252");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61235");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61214");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61238");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61274");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61233");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61241");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)) exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:sqlPort, exit_no_version:TRUE)) exit(0);
mysqlVer = infos["version"];
mysqlPath = infos["location"];

if(mysqlVer && mysqlVer =~ "^(5\.6)")
{
  if(version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.11"))
  {
    report = report_fixed_ver(installed_version:mysqlVer, fixed_version: "Apply the patch", install_path:mysqlPath);
    security_message(port:sqlPort, data:report);
    exit(0);
  }
}
