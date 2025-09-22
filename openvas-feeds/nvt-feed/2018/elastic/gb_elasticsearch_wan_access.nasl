# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108448");
  script_version("2025-09-03T08:26:15+0000");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-07-04 15:46:03 +0200 (Wed, 04 Jul 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Elastic Elasticsearch Public WAN (Internet) / Public LAN Accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_elasticsearch_consolidation.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9200);
  script_mandatory_keys("elastic/elasticsearch/http/detected", "elastic/elasticsearch/noauth",
                        "keys/is_public_addr");

  script_xref(name:"URL", value:"https://web.archive.org/web/20250503061805/https://duo.com/blog/beyond-s3-exposed-resources-on-aws");

  script_tag(name:"summary", value:"The script checks if the target host is running an Elastic
  Elasticsearch service accessible from a public WAN (Internet) / public LAN.");

  script_tag(name:"vuldetect", value:"Evaluate if the target host is running an Elastic
  Elasticsearch service accessible from a public WAN (Internet) / public LAN.

  Note: A configuration option 'Network type' to define if a scanned network should be seen as a
  public LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Only allow access to the Elastic Elasticsearch service from
  trusted sources or enable authentication via the X-Pack Elastic Stack extension.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("network_func.inc");

if( ! is_public_addr() )
  exit( 0 );

if( isnull(port = get_app_port( cpe:CPE, service:"www" )) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! get_kb_item( "elastic/elasticsearch/" + port + "/noauth" ) )
  exit( 99 );

security_message( port:port );
exit( 0 );
