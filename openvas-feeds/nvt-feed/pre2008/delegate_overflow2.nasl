# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17599");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-0861");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12867");
  script_name("Delegate < 8.10.3 Multiple Buffer Overflow Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Gain a shell remotely");
  script_dependencies("httpver.nasl", "proxy_use.nasl", "popserver_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/http_proxy", 8080, "Services/pop3", 110, 995);

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 8.10.3 or later.");

  script_tag(name:"summary", value:"Delegate is prone to multiple remote buffer overflow vulnerabilities.");

  script_tag(name:"impact", value:"The flaws may allow an attacker to execute arbitrary code on the
  remote host.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("pop3_func.inc");
include("version_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ports = pop3_get_ports();
foreach port(ports) {
  banner = pop3_get_banner(port:port);
  if( banner && egrep(pattern:"^\+OK Proxy-POP server \(Delegate/([0-7]\..*|8\.([0-9]\..*|10\.[0-2][^0-9])) by", string:banner)) {
    report = report_fixed_ver(installed_version:banner, fixed_version:"8.10.3");
    security_message(port:port, data:report);
  }
}

if(http_is_cgi_scan_disabled())
  exit(0);

port = service_get_port(default:8080, proto:"http_proxy");
banner = http_get_remote_headers(port:port);
if(!banner || "DeleGate" >!< banner)
  exit(0);

#Server: DeleGate/8.11.1
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*DeleGate/([0-7]\.|8\.([0-9]\.|10\.[0-2][^0-9]))", string:serv, icase:TRUE)) {
  report = report_fixed_ver(installed_version:serv, fixed_version:"8.10.3");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
