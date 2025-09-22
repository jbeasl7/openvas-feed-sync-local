# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805173");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2015-2567", "CVE-2015-0511", "CVE-2015-0508", "CVE-2015-0507",
                "CVE-2015-0506", "CVE-2015-0503", "CVE-2015-0500", "CVE-2015-0498");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-04-22 18:59:19 +0530 (Wed, 22 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle MySQL Multiple Unspecified vulnerabilities-04 (Apr 2015) - Windows");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors in the MySQL Server
  component via unknown vectors related to Server : Security : Privileges,
  Server : SP, Server : InnoDB, Server : Memcached, InnoDB, Server : Partition,
  Replication and some unknown vectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated remote attacker to cause a denial of service.");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.6.23 and earlier
  on windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74123");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74130");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74086");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74121");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74102");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74081");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74133");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sqlPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!mysqlVer = get_app_version(cpe:CPE, port:sqlPort)){
  exit(0);
}

if(mysqlVer =~ "^(5\.6)")
{
  if(version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.23"))
  {
    report = 'Installed version: ' + mysqlVer + '\n';
    security_message(data:report, port:sqlPort);
    exit(0);
  }
}

exit(99);
