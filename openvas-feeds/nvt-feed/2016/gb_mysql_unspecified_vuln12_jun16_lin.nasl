# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808124");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2015-4772", "CVE-2015-4771", "CVE-2015-4769", "CVE-2015-4761",
                "CVE-2015-4767", "CVE-2015-2641", "CVE-2015-2611", "CVE-2015-2617",
                "CVE-2015-2639", "CVE-2015-2661");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");

  script_tag(name:"creation_date", value:"2016-06-03 13:42:42 +0530 (Fri, 03 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle MySQL Multiple Unspecified Vulnerabilities-12 (Jun 2016) - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unspecified errors exist in the MySQL Server
  component via unknown vectors related to Server : Partition, Server : Memcached
  Server : Security : Firewall, RBR, Server : Optimizer, Server : InnoDB, DML,
  Server : I_S, Server : Pluggable Auth, Server : Security : Privileges, GIS,
  Partition and Client.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated remote attacker to affect confidentiality, integrity, and
  availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle MySQL Server 5.6.24 and earlier on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75781");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75835");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75753");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75770");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75844");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75815");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75762");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75774");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75760");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75813");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_unixoide");
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
  if(version_in_range(version:mysqlVer, test_version:"5.6", test_version2:"5.6.24"))
  {
    report = 'Installed version: ' + mysqlVer + '\n';
    security_message(data:report, port:sqlPort);
    exit(0);
  }
}
