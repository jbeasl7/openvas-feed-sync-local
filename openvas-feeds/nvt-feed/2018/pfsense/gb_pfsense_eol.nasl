# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pfsense:pfsense";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108435");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-04-07 12:17:00 +0200 (Sat, 07 Apr 2018)");
  script_name("pfSense End of Life (EOL) Detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_pfsense_consolidation.nasl");
  script_mandatory_keys("pfsense/detected");

  script_xref(name:"URL", value:"https://lists.pfsense.org/pipermail/list/2012-April/002017.html");
  script_xref(name:"URL", value:"https://doc.pfsense.org/index.php/Versions_of_pfSense_and_FreeBSD");

  script_tag(name:"summary", value:"The pfSense version on the remote host has reached the End of Life (EOL) and should
  not be used anymore.");

  script_tag(name:"impact", value:"An EOL version of pfSense is not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host.");

  script_tag(name:"solution", value:"Update the pfSense version on the remote host to a still supported version.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("date_func.inc");
include("eol_product.inc");
include("eol_shared.inc");
include("list_array_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ret = product_reached_eol( cpe:CPE, version:version ) ) {
  report = eol_build_message( name:"pfSense",
                              cpe:CPE,
                              version:version,
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
