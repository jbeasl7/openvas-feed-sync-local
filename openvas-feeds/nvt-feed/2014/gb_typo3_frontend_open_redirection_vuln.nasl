# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804213");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2010-3669");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-07 16:28:00 +0000 (Thu, 07 Nov 2019)");
  script_tag(name:"creation_date", value:"2014-01-07 18:00:17 +0530 (Tue, 07 Jan 2014)");
  script_name("TYPO3 Frontend Open Redirection Vulnerability (TYPO3-SA-2010-012) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("typo3/http/detected");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-sa-2010-012");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40742/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42029");

  script_tag(name:"summary", value:"TYPO3 is prone to an open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"An error exists in the frontend login box which fails to
  sanitize the 'redirect_url' parameter properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  phishing attacks.");

  script_tag(name:"affected", value:"TYPO3 versions prior to 4.2.13, 4.3.0 through 4.3.3 and 4.4.0
  only.");

  script_tag(name:"solution", value:"Update to version 4.2.13, 4.3.4, 4.4.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/typo3/?L=OUT&redirect_url=http://www.example.com";

req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);

if(res && res =~ "^HTTP/1\.[01] 302" && "Expires: 0" >< res &&
   "Location: http://www.example.com" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
