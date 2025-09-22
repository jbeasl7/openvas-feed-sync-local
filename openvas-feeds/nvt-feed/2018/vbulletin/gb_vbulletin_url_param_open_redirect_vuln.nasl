# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812677");
  script_version("2025-05-29T05:40:25+0000");
  script_cve_id("CVE-2018-6200");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-08 18:43:00 +0000 (Thu, 08 Feb 2018)");
  script_tag(name:"creation_date", value:"2018-02-08 12:48:53 +0530 (Thu, 08 Feb 2018)");
  script_name("vBulletin 3.x, 4.2.x <= 4.2.5 'url' GET Parameter Open Redirect Vulnerability - Active Check");

  script_tag(name:"summary", value:"vBulletin is prone to an open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The vulnerability exists due to insufficient sanitization of
  input passed via 'url' parameter to redirector.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to redirect
  users to arbitrary web sites and conduct phishing attacks.");

  script_tag(name:"affected", value:"vBulletin versions 3.x.x and 4.2.x through 4.2.5.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");
  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2018010251");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("vbulletin_http_detect.nasl");
  script_mandatory_keys("vbulletin/http/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

## base64(http://www.example.com/) == aHR0cDovL3d3dy5leGFtcGxlLmNvbS8=
foreach sub_url(make_list("http://www.example.com/", "aHR0cDovL3d3dy5leGFtcGxlLmNvbS8=")) {

  url = dir + "/redirector.php?url=" + sub_url;

  req = http_get_req(port: port, url: url);
  res = http_keepalive_send_recv(port:port, data:req);

  if((res =~ "^HTTP/1\.[01] 200" && "invalid URL being redirected" >!< res) &&
     ((res =~ "title>.*Redirecting.*</title>" && res =~ '<meta.*URL=http://www\\.example\\.com/">' && ">Redirecting" >< res) ||
      (res =~ "<input.*url=aHR0cDovL3d3dy5leGFtcGxlLmNvbS8=" && res =~ '<meta http-equiv="refresh" content=".*URL=http.*www\\.example\\.com'))) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
