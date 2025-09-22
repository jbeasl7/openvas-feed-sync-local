# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100436");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-01-11 11:18:50 +0100 (Mon, 11 Jan 2010)");
  script_cve_id("CVE-2009-4484");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MySQL 5.0.51a Unspecified RCE Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37640");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/dailydave/2010-q1/0002.html");
  script_xref(name:"URL", value:"http://intevydis.com/mysql_demo.html");

  script_tag(name:"summary", value:"MySQL 5.0.51a is prone to an unspecified remote code-execution
  vulnerability.");

  script_tag(name:"insight", value:"Very few technical details are currently available.");

  script_tag(name:"impact", value:"An attacker can leverage this issue to execute arbitrary code within
  the context of the vulnerable application. Failed exploit attempts
  will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"This issue affects MySQL 5.0.51a. Other versions may also be
  vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!ver = get_app_version(cpe:CPE, port:port)) exit(0);

if(ver =~ "^5\.0\.51a") {
  report = report_fixed_ver(installed_version:ver, fixed_version:"Unknown");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
