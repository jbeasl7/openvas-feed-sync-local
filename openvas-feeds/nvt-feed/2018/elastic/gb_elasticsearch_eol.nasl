# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113131");
  script_version("2025-09-03T08:26:15+0000");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-03-13 11:50:59 +0100 (Tue, 13 Mar 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elasticsearch End of Life (EOL) Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_consolidation.nasl");
  script_mandatory_keys("elastic/elasticsearch/detected");

  script_tag(name:"summary", value:"The Elasticsearch version on the remote host has reached
  the End of Life (EOL) and should not be used anymore.");

  script_tag(name:"impact", value:"An EOL version of Elasticsearch is not receiving any security
  updates from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to
  compromise the security of this host.");

  script_tag(name:"solution", value:"Update Elasticsearch to a version that still receives technical support and updates.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_xref(name:"URL", value:"https://www.elastic.co/support/eol");

  exit(0);
}

CPE = "cpe:/a:elastic:elasticsearch";

include("host_details.inc");
include("eol_product.inc");
include("eol_shared.inc");
include("list_array_func.inc");
include("date_func.inc");

 if( isnull( port = get_app_port( cpe: CPE ) ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( ret = product_reached_eol( cpe: CPE, version: version ) ) {
  report = eol_build_message( name: "Elasticsearch",
                              cpe: CPE,
                              version: version,
                              eol_version: ret["eol_version"],
                              eol_date: ret["eol_date"],
                              eol_type: "prod" );

  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
