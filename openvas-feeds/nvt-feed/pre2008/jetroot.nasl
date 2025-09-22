# SPDX-FileCopyrightText: 2004 facq
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12227");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Hewlett-Packard Web Jetadmin <= 6.5 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 facq");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports(8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.phenoelit.de/stuff/HP_Web_Jetadmin_advisory.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9973");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/15989");

  script_tag(name:"summary", value:"The remote Hewlett-Packard Web Jetadmin is vulnerable to
  multiple exploits. This includes, but is not limited to, full remote administrative access.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can execute code remotely with SYSTEM level (or root)
  privileges by invoking the ExecuteFile function. To further exacerbate this issue, there is
  working exploit code for multiple vulnerabilities within this product.");

  script_tag(name:"solution", value:"The issues are resolved in Hewlett-Packard Web Jetadmin version
  7.5.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = 8000;
if(!get_port_state(port))
  exit(0);

# nb:
# - http_report_vuln_url() used below might fork on multiple hostnames and should be always before
#   the first http_send_recv() call
# - For simplicity within such an older check we're just calling http_host_name() instead directly
#   here as it will also fork
http_host_name(port:port);

url = "/plugins/hpjwja/help/about.hts";
r = http_send_recv(port:port, data:string("GET ", url, " HTTP/1.0\r\n\r\n"));
if(!r)
  exit(0);

if(r =~ "^HTTP/1\.[01] 200" && "Server: HP-Web-Server" >< r) {

  r = ereg_replace(pattern:"<b>|</b>", string:r, replace:"<>");
  r = ereg_replace(pattern:"<[^>]+>", string:r, replace:"");
  r = ereg_replace(pattern:"[[:space:]]+", string:r, replace:" ");
  r = ereg_replace(pattern:" <>", string:r, replace:"<>");
  r = ereg_replace(pattern:"<> ", string:r, replace:"<>");

  if(r =~ "<>HP Web JetAdmin Version<>6.5" || # tested
     r =~ "<>HP Web JetAdmin Version<>6.2" || # not tested
     r =~ "<>HP Web JetAdmin Version<>7.0") { # not tested
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
  }
  exit(99);
}

exit(0);
