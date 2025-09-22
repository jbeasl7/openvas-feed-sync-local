# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10795");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Lotus Notes Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 SecuriTeam");
  script_family("Web Servers");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.securiteam.com/securitynews/6W0030U35W.html");
  script_xref(name:"URL", value:"http://online.securityfocus.com/archive/1/223810");

  script_tag(name:"solution", value:"To disable this behavior open names.nsf and edit the
  Servers document in the Server view. From the Internet Protocols tab set 'Allow HTTP Clients
  to browse databases' to No. This command doesn't affect a single database - it is a server-wide issue.");

  script_tag(name:"summary", value:"A default behavior of Lotus Notes allows remote users to enumerate existing
  databases on a remote Domino (Lotus Notes) server. This information is considered sensitive, since it might reveal
  versions, logs, statistics, etc.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/?OpenServer";

if( http_vuln_check( port:port, url:url, check_header:TRUE,
    pattern:"!-- Lotus-Domino",
    extra_check: "/icons/abook.gif" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
