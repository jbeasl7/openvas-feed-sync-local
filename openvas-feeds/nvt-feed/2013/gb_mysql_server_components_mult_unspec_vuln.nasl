# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803808");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2012-1690", "CVE-2012-1688", "CVE-2012-1703");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-06-04 13:12:18 +0530 (Tue, 04 Jun 2013)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_name("MySQL Server Components Multiple Unspecified Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53058");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53067");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53074");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html#AppendixMSQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("oracle/mysql/detected", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation could allow remote authenticated users to affect
  availability via unknown vectors.");

  script_tag(name:"affected", value:"MySQL version 5.1.x before 5.1.62 and 5.5.x before 5.5.22.");

  script_tag(name:"insight", value:"Multiple unspecified errors exist in the Server Optimizer and
  Server DML components.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"MySQL is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers && vers =~ "^5\.[15]") {
  if(version_in_range(version:vers, test_version:"5.1", test_version2:"5.1.61") ||
     version_in_range(version:vers, test_version:"5.5", test_version2:"5.5.21")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
