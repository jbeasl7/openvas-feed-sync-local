# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803219");
  script_version("2024-07-19T05:05:32+0000");
  script_cve_id("CVE-2012-3488", "CVE-2012-3489");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-07-19 05:05:32 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 03:22:42 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-01-24 17:08:52 +0530 (Thu, 24 Jan 2013)");
  script_name("PostgreSQL 'xml_parse()' And 'xslt_process()' Multiple Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50218");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55072");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55074");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027408");
  script_xref(name:"URL", value:"http://www.postgresql.org/about/news/1407");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_postgresql_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to modify data, obtain sensitive
  information or trigger outbound traffic to arbitrary external hosts.");

  script_tag(name:"affected", value:"PostgreSQL versions 8.3 before 8.3.20, 8.4 before 8.4.13,
  9.0 before 9.0.9, and 9.1 before 9.1.5 on Windows.");

  script_tag(name:"insight", value:"- An error exists within the 'xml_parse()' function when parsing DTD data
  within XML documents.

  - An error exists within the 'xslt_process()' when parsing XSLT style sheets.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL 8.3.20, 8.4.13, 9.0.9 or 9.1.5 or later.");

  script_tag(name:"summary", value:"PostgreSQL is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

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
if(vers !~ "^[89]\.")
  exit(99);

if(version_in_range(version:vers, test_version:"8.3", test_version2:"8.3.19") ||
   version_in_range(version:vers, test_version:"8.4", test_version2:"8.4.12") ||
   version_in_range(version:vers, test_version:"9.0", test_version2:"9.0.8") ||
   version_in_range(version:vers, test_version:"9.1", test_version2:"9.1.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:loc);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
