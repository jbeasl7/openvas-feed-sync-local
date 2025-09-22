# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802495");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-11-21 10:48:20 +0530 (Wed, 21 Nov 2012)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("MODX CMS 1.x - 2.x Brute Force and Path Disclosure Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_http_detect.nasl");
  script_mandatory_keys("modx/cms/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"MODX CMS is prone to brute force and path disclosure
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to obtain
  sensitive information that could aid in further attacks.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - In login form (manager/index.php) there is no reliable protection from brute force attacks.

  - Insufficient error checking, allows remote attackers to obtain sensitive information via a
  direct request to a .php file, which reveals the installation path in an error message.");

  script_tag(name:"affected", value:"MODX CMF versions 1.x (Evolution) and 2.x (Revolution).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Nov/142");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118240/modx-brutedisclose.txt");

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

url = dir + "/manager/includes/browsercheck.inc.php";

# Don't use check_headers. A 500 error is thrown here on this request
if( http_vuln_check( port:port, url:url, pattern:"Failed opening required 'MODX_BASE_PAT.*browsercheck.inc.php",
                     extra_check:make_list( 'phpSniff.class.php','MODX_BASE_PATH' ) ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
