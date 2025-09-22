# SPDX-FileCopyrightText: 2000 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10572");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("IIS 5.0 Sample App vulnerable to cross-site scripting attack");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2000 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2000-02.html");

  script_tag(name:"solution", value:"Always remove sample applications from productions servers.

  In this case, remove the entire /iissamples folder.");

  script_tag(name:"summary", value:"The script /iissamples/sdk/asp/interaction/Form_JScript.asp
  (or Form_VBScript.asp) allows you to insert information into a form
  field and once submitted re-displays the page, printing the text you entered.

  This .asp doesn't perform any input validation, and hence you can input a
  string like:

  <SCRIPT>alert(document.domain)</SCRIPT>.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_asp(port:port))
  exit(0);

url = "/iissamples/sdk/asp/interaction/Form_JScript.asp";
if(http_is_cgi_installed_ka(item:url, port:port)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
