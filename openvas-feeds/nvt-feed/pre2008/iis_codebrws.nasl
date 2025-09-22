# SPDX-FileCopyrightText: 2002 Matt Moore / HD Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10956");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-1999-0739");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Microsoft IIS 'Codebrws.asp' Source Disclosure Vulnerability - Active Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Matt Moore / HD Moore");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_tag(name:"solution", value:"Remove the /IISSamples virtual directory using the Internet Services Manager.

  If for some reason this is not possible, removing the following ASP script will fix the problem:

  This path assumes that you installed IIS in c:\inetpub

  c:\inetpub\iissamples\sdk\asp\docs\CodeBrws.asp");

  script_tag(name:"summary", value:"Microsoft's IIS 5.0 web server is shipped with a set of
  sample files to demonstrate different features of the ASP language. One of these sample
  files allows a remote user to view the source of any file in the web root with the extension
  .asp, .inc, .htm, or .html.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/iissamples/sdk/asp/docs/codebrws.asp";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(data:req, port:port);
if(!res)
  exit(0);

if("View Active Server Page Source" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
