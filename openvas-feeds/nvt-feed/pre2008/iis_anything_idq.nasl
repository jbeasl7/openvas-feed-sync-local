# SPDX-FileCopyrightText: 2000 Filipe Custodio
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10492");
  script_version("2024-04-15T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-04-15 05:05:35 +0000 (Mon, 15 Apr 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0071", "CVE-2000-0097", "CVE-2000-0098", "CVE-2000-0302");
  script_name("Microsoft IIS IDA/IDQ Path Disclosure Vulnerability (MS00-006) - Active Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2000 Filipe Custodio");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-006");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210208184628/http://www.securityfocus.com/bid/1084/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210208184628/http://www.securityfocus.com/bid/1065/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210208184628/http://www.securityfocus.com/bid/950/");

  script_tag(name:"summary", value:"IIS 4.0 allows a remote attacker to obtain the real pathname of
  the document root by requesting non-existent files with .ida or .idq extensions.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.

  Note: This VT checks for the existence of CVE-2000-0071.");

  script_tag(name:"impact", value:"An attacker may use this flaw to gain more information about the
  remote host, and hence make more focused attacks.");

  script_tag(name:"solution", value:"Select 'Preferences ->Home directory ->Application', and check
  the checkbox 'Check if file exists' for the ISAPI mappings of your server.");

  # nb: Response check doesn't look that reliable these days...
  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/anything.idq";
req = http_get(item:url, port:port);
r = http_send_recv(port:port, data:req);

str = egrep(pattern:"^<HTML>", string:r) - "<HTML>";
str = tolower(str);

if(egrep(pattern:"[a-z]\:\\.*anything", string:str)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
} else {
  url = "/anything.ida";
  req = http_get(item:url, port:port);
  r = http_send_recv(port:port, data:req);
  str = egrep(pattern:"^<HTML>", string:r) - "<HTML>";
  str = tolower(str);
  if(egrep(pattern:"[a-z]\:\\.*anything", string:str)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
