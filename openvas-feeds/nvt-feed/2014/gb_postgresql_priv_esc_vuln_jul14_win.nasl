# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804711");
  script_version("2024-07-19T05:05:32+0000");
  script_cve_id("CVE-2014-0067");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2014-07-07 15:34:21 +0530 (Mon, 07 Jul 2014)");
  script_name("PostgreSQL 'make check' Local Privilege Escalation Vulnerability (Jul 2014) - Windows");

  script_tag(name:"summary", value:"PostgreSQL is prone to a local privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to an error when creating a PostgreSQL database cluster during
  'make check'.");

  script_tag(name:"impact", value:"Successful exploitation may allow local attacker to gain temporary server
  access and elevated privileges.");

  script_tag(name:"affected", value:"PostgreSQL version 9.3.3 and earlier");

  script_tag(name:"solution", value:"Update to version 9.3.6, 9.4.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57054");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65721");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/91459");
  script_xref(name:"URL", value:"http://wiki.postgresql.org/wiki/20140220securityrelease");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
loc = infos["location"];

if(vers !~ "^(8\.4|9\.[0-3])\.")
  exit(99);

if(version_in_range(version:vers, test_version:"8.4", test_version2:"9.3.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
