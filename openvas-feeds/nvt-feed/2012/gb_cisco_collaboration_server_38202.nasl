# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103403");
  script_cve_id("CVE-2010-0642");
  script_version("2024-01-09T05:06:46+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Cisco Collaboration Server 5 Source Code Disclosure Vulnerabilities - Active Check");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38202");
  script_xref(name:"URL", value:"http://www.cisco.com/en/US/products/sw/custcosw/ps747/prod_eol_notice09186a008032d4d0.html");

  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2012-01-27 13:35:51 +0100 (Fri, 27 Jan 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("CISCO");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Cisco Collaboration Server is prone to multiple vulnerabilities
  that may allow remote attackers to obtain sourcecode, which may aid them in further attacks.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"Cisco Collaboration Server 5 is vulnerable. Other versions may
  be affected as well.

  NOTE: The vendor has discontinued this product.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

url = "/webline/html/admin/wcs/LoginPage.jhtml?oper=login&dest=%2Fadmin%2FCiscoAdmin.jhtml";

if(http_vuln_check(port:port, url:url, pattern:"Cisco Administration Log In", usecache:TRUE)) {

  url = "/webline/html/admin/wcs/LoginPage.jhtml%00";

  if(http_vuln_check(port:port, url:url, pattern:"<java>", extra_check:make_list("out.println", "AdminDBAuthHelper"))) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
