# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sql_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108188");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-06-26 09:48:20 +0200 (Mon, 26 Jun 2017)");

  script_name("Microsoft SQL (MSSQL) Server End of Life (EOL) Detection");

  script_copyright("Copyright (C) 2017 Greenbone AG");

  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_microsoft_sql_server_consolidation.nasl");
  script_mandatory_keys("microsoft/sqlserver/detected");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=sql%20server&Filter=FilterNO");
  script_xref(name:"URL", value:"https://en.wikipedia.org/wiki/History_of_Microsoft_SQL_Server#Release_summary");

  script_tag(name:"summary", value:"The Microsoft SQL (MSSQL) Server version on the remote host has
  reached the end of life (EOL) and should not be used anymore.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"impact", value:"An EOL version of Microsoft SQL Server is not receiving any
  security updates from the vendor. Unfixed security vulnerabilities might be leveraged by an
  attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the Microsoft SQL Server version on the remote host to
  a still supported version.

  Note: Please create an override for this result if the target is a Azure SQL Managed/Azure SQL DB
  instance.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("date_func.inc");
include("eol_product.inc");
include("eol_shared.inc");
include("list_array_func.inc");
include("host_details.inc");
include("mssql.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_full( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
full_cpe = infos["full_cpe"];
location = infos["location"];

# Handle CPE/versions e.g. like cpe:/a:microsoft:sql_server:2008:r2:sp2
tmp = split( full_cpe, sep:":", keep:FALSE );
if( ! ereg( pattern:tmp[max_index( tmp ) - 1], string:version ) )
  version += tmp[max_index( tmp ) - 1];

if( ret = product_reached_eol( cpe:CPE, version:version ) ) {

  rls = mssql_get_rel_name( version:infos["internal_version"] );
  if( rls )
    name = "Microsoft SQL (MSSQL) Server " + rls;
  else
    name = "Microsoft SQL (MSSQL) Server";

  report = eol_build_message( name:name,
                              cpe:full_cpe,
                              location:location,
                              eol_version:rls,
                              eol_date:ret["eol_date"],
                              eol_type:"prod",
                              skip_version:TRUE );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
