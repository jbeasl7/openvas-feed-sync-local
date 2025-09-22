# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:greenbone:greenbone_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105126");
  script_cve_id("CVE-2014-9220");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-11-30 14:20:39 +0200 (Sun, 30 Nov 2014)");
  script_name("Greenbone OS SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_greenbone_os_consolidation.nasl");
  script_mandatory_keys("greenbone/gos/detected");

  script_xref(name:"URL", value:"https://www.greenbone.net/en/security-response-team/#toggle-id-4");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71360");

  script_tag(name:"summary", value:"GreenboneOS is prone to a SQL injection vulnerability");

  script_tag(name:"impact", value:"A successful attack is possible if the attacker controls a user
  account for the web interface or for OMP. The attacker will gain read access to the database.");

  script_tag(name:"insight", value:"A software bug in OpenVAS Manager as used in Greenbone OS allows
  remote attackers to inject SQL code that reads data from the database.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to Greenbone OS 2.2.0-34/3.0.29.");

  script_tag(name:"affected", value:"Greenbone OS 2.2.0-1 up to 2.2.0-33.

  Greenbone OS 3.0.1 up to 3.0.28.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_kb_item("greenbone/gos/version") ) exit( 0 );
version = str_replace( string:version, find:"-", replace:"." );

if( version_is_less_equal( version:version, test_version:"2.2.0.33" ) ||
    version_in_range( version:version, test_version:"3.0.1", test_version2:"3.0.28" ) )
{

  if( version =~ "^2\.2" )
    fixed_version = '2.2.0.34';
  else
    fixed_version = '3.0.29';

  report = report_fixed_ver( installed_version:version, fixed_version:fixed_version );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
