# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801573");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_cve_id("CVE-2010-3840");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("MySQL 'Gis_line_string::init_from_wkb()' DOS Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42875");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43676");
  script_xref(name:"URL", value:"http://bugs.mysql.com/bug.php?id=54568");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-51.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow users to cause a denial of service and
  to execute arbitrary code.");

  script_tag(name:"affected", value:"MySQL version 5.1 before 5.1.51.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'Gis_line_string::init_from_wkb()'
  function in 'sql/spatial.cc', allows remote authenticated users to cause a
  denial of service by calling the PolyFromWKB function with WKB data
  containing a crafted number of line strings or line points.");

  script_tag(name:"solution", value:"Upgrade to MySQL version 5.1.51.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"MySQL is prone to a denial of service (DoS) vulnerability.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"5.1", test_version2:"5.1.50")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"5.1 - 5.1.50");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
