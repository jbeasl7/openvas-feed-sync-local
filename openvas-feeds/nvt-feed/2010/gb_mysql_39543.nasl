# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100586");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-04-20 13:41:39 +0200 (Tue, 20 Apr 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-1621");
  script_name("MySQL UNINSTALL PLUGIN Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39543");
  script_xref(name:"URL", value:"http://lists.mysql.com/commits/103144");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-46.html");

  script_tag(name:"summary", value:"MySQL is prone to a security bypass vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to uninstall plugins without having
  sufficient privileges. This may result in denial-of-service conditions.");

  script_tag(name:"affected", value:"Versions of MySQL 5.1.45 and prior are affected.");

  script_tag(name:"solution", value:"A fix in the source code repository is available. Please see the
  references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if(ver =~ "^5\.1" && version_is_less_equal(version: ver, test_version: "5.1.45")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"5.1.45");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
