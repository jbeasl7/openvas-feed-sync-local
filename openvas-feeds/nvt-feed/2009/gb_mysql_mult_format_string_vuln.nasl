# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800842");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2446");
  script_name("MySQL 'sql_parse.cc' Multiple Format String Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35767");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35609");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51614");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504799/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow remote authenticated users to cause a Denial
  of Service and possibly have unspecified other attacks.");

  script_tag(name:"affected", value:"MySQL version 4.0.0 to 5.0.83 on all running platform.");

  script_tag(name:"insight", value:"The flaws are due to error in the 'dispatch_command' function in sql_parse.cc
  in libmysqld/ which can caused via format string specifiers in a database name
  in a 'COM_CREATE_DB' or 'COM_DROP_DB' request.");

  script_tag(name:"solution", value:"Upgrade to MySQL version 5.1.36 or later.");

  script_tag(name:"summary", value:"MySQL is prone to Multiple Format String vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"4.0", test_version2:"5.0.83")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"4.0 - 5.0.83");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
