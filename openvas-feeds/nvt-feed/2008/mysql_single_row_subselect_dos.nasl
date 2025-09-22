# SPDX-FileCopyrightText: 2008 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80075");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2007-1420");
  script_xref(name:"OSVDB", value:"33974");
  script_name("MySQL < 5.0.37 Single Row Subselect Remote DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 David Maciejak");
  script_family("Databases");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_tag(name:"summary", value:"MySQL is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"According to its banner, the version of MySQL on the remote host
  is older than 5.0.37. Such versions are vulnerable to a remote denial of service when processing
  certain single row subselect queries.");

  script_tag(name:"impact", value:"A malicious user can crash the service via a specially-crafted
  SQL query.");

  script_tag(name:"solution", value:"Update to version 5.0.37 or later.");

  script_xref(name:"URL", value:"http://www.sec-consult.com/284.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22900");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/462339/100/0/threaded");
  script_xref(name:"URL", value:"http://dev.mysql.com/doc/refman/5.0/en/releasenotes-cs-5-0-37.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if(ereg(pattern:"^5\.0\.([0-9]($|[^0-9])|[12][0-9]($|[^0-9])|3[0-6]($|[^0-9]))", string:ver)) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"5.0.37");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
