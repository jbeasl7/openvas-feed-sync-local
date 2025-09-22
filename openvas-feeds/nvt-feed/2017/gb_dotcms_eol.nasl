# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dotcms:dotcms";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112093");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-10-23 16:45:53 +0200 (Mon, 23 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("dotCMS End of Life (EOL) Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dotcms_http_detect.nasl");
  script_mandatory_keys("dotcms/detected");

  script_tag(name:"summary", value:"The dotCMS version on the remote host has reached the End of
  Life (EOL) and should not be used anymore.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"impact", value:"An EOL version of dotCMS is not receiving any security updates
  from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise
  the security of this host.");

  script_tag(name:"solution", value:"Update the dotCMS version on the remote host to a still
  supported version.");

  script_xref(name:"URL", value:"https://dotcms.com/docs/latest/release-lifecycle");

  exit(0);
}

include("date_func.inc");
include("eol_product.inc");
include("eol_shared.inc");
include("list_array_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version  = infos["version"];
location = infos["location"];

if( ret = product_reached_eol( cpe: CPE, version: version ) ) {
  report = eol_build_message( name: "dotCMS",
                              cpe: CPE,
                              version: version,
                              location: location,
                              eol_version: ret["eol_version"],
                              eol_date: ret["eol_date"],
                              eol_type: "prod" );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
