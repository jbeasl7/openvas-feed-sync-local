# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100843");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-10-06 12:55:58 +0200 (Wed, 06 Oct 2010)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3433");
  script_name("PostgreSQL PL/Perl and PL/Tcl Local Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_postgresql_consolidation.nasl");
  script_mandatory_keys("postgresql/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43747");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/9.0/static/release-9-0-1.html");

  script_tag(name:"summary", value:"PostgreSQL is prone to a local privilege escalation vulnerability.");

  script_tag(name:"impact", value:"Exploiting this issue allows local attackers to gain elevated
  privileges and execute arbitrary commands with the privileges of the victim.");

  script_tag(name:"affected", value:"Versions prior to PostgreSQL 9.0.1 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
loc = infos["location"];

if( version_is_less( version:vers, test_version:"9.0.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
