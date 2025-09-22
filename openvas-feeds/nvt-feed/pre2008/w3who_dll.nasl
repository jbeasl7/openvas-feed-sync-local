# SPDX-FileCopyrightText: 2004 Nicolas Gregoire
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15910");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2004-1133", "CVE-2004-1134");
  script_name("w3who.dll Buffer Overflow / XSS Vulnerability - Active Check");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2004 Nicolas Gregoire");
  script_family("Web application abuses");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_tag(name:"solution", value:"Delete this file.");

  script_tag(name:"summary", value:"The Windows 2000 Resource Kit ships with a DLL that displays
  the browser client context. It lists security identifiers, privileges and $ENV variables.

  The scanner has determined that this file is installed on the remote host.");

  script_tag(name:"impact", value:"The w3who.dll ISAPI may allow an attacker to execute arbitrary
  commands on this host, through a buffer overflow, or to mount XSS attacks.");

  script_xref(name:"URL", value:"http://www.exaprobe.com/labs/advisories/esa-2004-1206.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11820");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

# nb: No get_app_location() as IIS is not "directly" affected and the initial version of
# this VT had only checked for the banner of IIS.
if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

host = http_host_name(port:port);

url = "/scripts/w3who.dll";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("Access Token" >< res) {

  report = http_report_vuln_url(port:port, url:url);
  if(safe_checks()) {
    security_message(port:port, data:report);
    exit(0);
  }

  useragent = http_get_user_agent();
  req = string("GET /scripts/w3who.dll?", crap(600), " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n");
  r = http_send_recv(port:port, data:req);

  # The page content is subject to localization
  # Matching on headers and title
  if(r =~ "^HTTP/1\.[01] 500" &&
     "<html><head><title>Error</title>" >< r)
    security_message(port:port, data:report);
}

exit(99);
