# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15449");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11357");
  script_cve_id("CVE-2004-0835", "CVE-2004-0837");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MySQL < 3.23.59, 4.x < 4.0.21 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_mysql_mariadb_remote_detect.nasl");
  script_mandatory_keys("oracle/mysql/detected");

  script_tag(name:"solution", value:"Update to version 3.23.59, 4.0.21 or later.");

  script_tag(name:"summary", value:"MySQL is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The remote version of this software is vulnerable to specially
  crafted ALTER TABLE SQL query which can be exploited to bypass some applied security restrictions
  or cause a denial of service. To exploit this flaw, an attacker would need the ability to execute
  arbitrary SQL statements on the remote host.");

  script_tag(name:"affected", value:"MySQL prior to 3.23.59 and 4.x prior to 4.0.21.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!ver = get_app_version(cpe:CPE, port:port))exit(0);

if(ereg(pattern:"^(3\.([0-9]\.|1[0-9]\.|2[0-2]\.|23\.(([0-9]|[1-4][0-9]|5[0-8])[^0-9]))|4\.0\.([0-9]|1[0-9]|20)[^0-9])", string:ver))security_message(port);

