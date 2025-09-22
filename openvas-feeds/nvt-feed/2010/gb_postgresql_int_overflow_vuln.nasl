# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902139");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-0733");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_name("PostgreSQL Hash Table Integer Overflow Vulnerability");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_postgresql_consolidation.nasl");
  script_mandatory_keys("postgresql/detected");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546621");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/03/16/10");
  script_xref(name:"URL", value:"http://archives.postgresql.org/pgsql-bugs/2009-10/msg00310.php");
  script_xref(name:"URL", value:"http://archives.postgresql.org/pgsql-bugs/2009-10/msg00289.php");
  script_xref(name:"URL", value:"http://archives.postgresql.org/pgsql-bugs/2009-10/msg00287.php");
  script_xref(name:"URL", value:"http://archives.postgresql.org/pgsql-bugs/2009-10/msg00277.php");
  script_xref(name:"URL", value:"http://git.postgresql.org/gitweb?p=postgresql.git;a=commitdiff;h=64b057e6823655fb6c5d1f24a28f236b94dd6c54");

  script_tag(name:"impact", value:"Successful exploitation could allow execution of specially-crafted sql query
  which once processed would lead to denial of service (postgresql daemon crash).");

  script_tag(name:"affected", value:"PostgreSQL version 8.4.1 and prior and 8.5 through 8.5alpha2.");

  script_tag(name:"insight", value:"The flaw is due to an integer overflow error in 'src/backend/executor/nodeHash.c',
  when used to calculate size for the hashtable for joined relations.");

  script_tag(name:"summary", value:"PostgreSQL is prone to an integer overflow vulnerability.");

  script_tag(name:"solution", value:"Apply the patch linked in the references.");

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

if( version_is_less_equal( version:vers, test_version:"8.4.1" ) ||
    version_in_range( version:vers, test_version:"8.5", test_version2:"8.5.alpha2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
