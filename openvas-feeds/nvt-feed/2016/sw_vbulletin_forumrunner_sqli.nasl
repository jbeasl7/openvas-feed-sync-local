# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111112");
  script_version("2025-05-29T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"creation_date", value:"2016-07-24 14:00:00 +0200 (Sun, 24 Jul 2016)");
  script_cve_id("CVE-2016-6195");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-21 01:29:00 +0000 (Mon, 21 Aug 2017)");
  script_name("vBulletin 3.6.x to 4.2.2/4.2.3 Forumrunner 'request.php' SQLi Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("vbulletin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vbulletin/http/detected");

  script_xref(name:"URL", value:"https://enumerated.wordpress.com/2016/07/11/1/");
  script_xref(name:"URL", value:"http://www.vbulletin.com/forum/node/4345175");
  script_xref(name:"URL", value:"http://members.vbulletin.com/patches.php");

  script_tag(name:"summary", value:"The vBulletin core forumrunner addon (enabled by default) is
  affected by an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation will allow an unauthenticated remote
  attacker to execute arbitrary SQL commands via the 'postids' parameter to request.php.");

  script_tag(name:"affected", value:"vBulletin 3.6.x to 4.2.2 (before Patch Level 5) / 4.2.3 (before
  Patch Level 1) with an enabled forumrunner addon.");

  script_tag(name:"solution", value:"The Patches 4.2.2 Patch Level 5 and 4.2.3 Patch Level 1 are
  available at the vBulletin member's area.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

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

url = dir + "/forumrunner/request.php?cmd=get_spam_data&d=1&postids='1";

if( http_vuln_check( port:port, url:url, pattern:"(database has encountered a problem|image\.php\?type=dberror)" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
