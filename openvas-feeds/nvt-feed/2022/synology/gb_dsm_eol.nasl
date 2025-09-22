# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170274");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-12-22 09:12:14 +0000 (Thu, 22 Dec 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) End of Life (EOL) Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"The Synology DiskStation Manager (DSM) version on the remote
  host has reached the End of Life (EOL) and should not be used anymore.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"impact", value:"An EOL version of Synology DSM is not receiving any security
  updates from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to
  compromise the security of this host.");

  script_tag(name:"solution", value:"Update the Synology DSM version on the remote host to a still
  supported version.");

  script_xref(name:"URL", value:"https://kb.synology.com/en-us/WP/Synology_Security_White_Paper/3");

  exit(0);
}

include("host_details.inc");
include("date_func.inc");
include("eol_product.inc");
include("eol_shared.inc");
include("list_array_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ret = product_reached_eol( cpe:CPE, version:version ) ) {
  report = eol_build_message( name:"Synology DiskStation Manager (DSM)",
                              cpe:CPE,
                              version:version,
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
