# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103471");
  script_version("2025-09-09T05:38:49+0000");
  script_cve_id("CVE-2012-0882");
  script_name("MySQL 'yaSSL' RCE Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51925");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52154");
  script_xref(name:"URL", value:"https://lists.immunityinc.com/pipermail/canvas/2012-February/000011.html");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-04-19 11:22:35 +0200 (Thu, 19 Apr 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_tag(name:"summary", value:"MySQL is prone to an unspecified remote code execution (RCE) vulnerability.");
  script_tag(name:"impact", value:"Attackers can exploit this vulnerability to execute arbitrary code in
the context of the affected application.");
  script_tag(name:"insight", value:"Limited information is available regarding this issue. This script will
be updated as more information becomes available.");
  script_tag(name:"affected", value:"MySQL 5.5.20 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution", value:"The issues seem to be fixed in MySQL versions 5.5.22 and 5.1.62.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

version = eregmatch(pattern:"([0-9.a-z]+)", string:version);

if(!isnull(version[1])) {
  if(version_in_range(version:version[1], test_version:"5.5", test_version2:"5.5.21")) {
    report = report_fixed_ver(installed_version:version[1], vulnerable_range:"5.5.22");
    security_message(port:port, data:report);
    exit(0);
  }
  if(version_in_range(version:version[1], test_version:"5.1", test_version2:"5.1.61")) {
    report = report_fixed_ver(installed_version:version[1], vulnerable_range:"5.1.62");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
