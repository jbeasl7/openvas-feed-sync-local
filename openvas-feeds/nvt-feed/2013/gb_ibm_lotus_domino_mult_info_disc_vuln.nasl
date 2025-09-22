# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803755");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-04 16:22:08 +0530 (Wed, 04 Sep 2013)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("IBM Lotus Domino Multiple Information Disclosure Vulnerabilities");

  script_xref(name:"URL", value:"http://websecurity.com.ua/5829");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Apr/248");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hcl/domino/detected");

  script_tag(name:"summary", value:"Lotus Domino Server is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the direct HTTP request to restricted config files and check it is
  possible to read the configuration file content or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"The flaws are due to the multiple config files (names.nsf, admin4.nsf,
  catalog.nsf, events4.nsf) are accessible without authentication, there is a leakage of information about web
  server configuration.");

  script_tag(name:"affected", value:"IBM Lotus Domino 8.5.3, 8.5.4, 9.0 and previous versions.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to access web server
  configuration information.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/names.nsf";

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"_domino_name",
                     extra_check: make_list("_wMainFrameset", "OpenPage" ) ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
