# SPDX-FileCopyrightText: 2004 Michael J. Richardson
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14718");
  script_version("2024-12-04T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-12-04 05:05:48 +0000 (Wed, 04 Dec 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  # nb: Not listed on the advisory below but CVE description and reference is matching this flaw and
  # the CVE also existed in this VT since the creation of it
  script_cve_id("CVE-2002-1094");
  script_name("Cisco VPN 3000 Series Concentrator Information Disclosure Vulnerability (CSCdu35577) - Active Check");
  script_category(ACT_GATHER_INFO); # nb: No ACT_ATTACK needed
  script_copyright("Copyright (C) 2004 Michael J. Richardson");
  script_family("CISCO");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20031211162329/http://www.cisco.com/warp/public/707/vpn3k-multiple-vuln-pub.shtml");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210129023720/http://www.securityfocus.com/bid/5624");
  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20020903-vpn3k-vulnerability.html");

  script_tag(name:"summary", value:"Cisco VPN 3000 series concentrators are prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The Cisco VPN 3000 series concentrators give out too much
  information in application layer banners. The SSH banner gives out information about the device
  apart from the SSH version numbers. The FTP banner gives information about the device and the
  local time. An incorrect HTTP page request gives out information about the device, the name of the
  person who compiled the software and the time of compilation.

  This vulnerability is documented as Cisco bug ID CSCdu35577.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = "/vt-test-non-existent.html";
res = http_get_cache(item:url, port:port);
if(!res)
  exit(0);

# nb: Keep this HTTP pattern because we don't know if such an old device had answered with e.g.
# a HTTP/0.9 code...
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200", string:res) && "<b>Software Version:</b>" >< res && "Cisco Systems, Inc./VPN 3000 Concentrator Version" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  report += '\n\nThe following software version was identified:\n\n' + egrep(pattern:"Cisco Systems, Inc./VPN 3000 Concentrator Version", string:res);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
