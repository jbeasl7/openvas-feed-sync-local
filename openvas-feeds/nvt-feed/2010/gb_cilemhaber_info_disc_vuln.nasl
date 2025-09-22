# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801605");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Cilem Haber Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62249");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15199/");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to download
  the database and obtain sensitive information.");

  script_tag(name:"affected", value:"Cilem Haber Version 1.4.4");

  script_tag(name:"insight", value:"The flaw is caused by improper restrictions on the
  'cilemhaber.mdb' database file. By sending a direct request, a remote attacker
  could download the database and obtain sensitive information.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Cilem Haber is prone to an information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if( ! http_can_host_asp( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/cilemhaber", "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/www/default.asp", port:port );

  if( res =~ "^HTTP/1\.[01] 200" && "cilemhaber" >< res ) {

    url = dir + "/db/cilemhaber.mdb";
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req );

    if( res =~ "^HTTP/1\.[01] 200" && "Standard Jet DB" >< res ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
