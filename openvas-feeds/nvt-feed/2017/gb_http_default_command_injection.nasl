# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112054");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2017-09-27 09:42:21 +0200 (Wed, 27 Sep 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Generic HTTP Command Injection Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/Code_Injection");

  script_tag(name:"summary", value:"The script checks for generic code vulnerabilities in web pages.

  NOTE: Please enable 'Enable generic web application scanning' within the VT 'Global variable settings'
  (OID: 1.3.6.1.4.1.25623.1.0.12288) if you want to run this script.");

  script_tag(name:"vuldetect", value:"Tries to inject commands into the machine via GET parameter. If successful,
  the vulnerability is confirmed.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute arbitrary commands
  on the host machine.");

  script_tag(name:"solution", value:"Please contact the specific vendor for a solution.");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");

# nb: We also don't want to run if optimize_test is set to "no"
if( http_is_cgi_scan_disabled() ||
    get_kb_item( "global_settings/disable_generic_webapp_scanning" ) )
  exit( 0 );

port = http_get_port(default:80);
host = http_host_name(dont_add_port:TRUE);

cgis = http_get_kb_cgis(port:port, host:host);
if(!cgis) exit(0);

cmds = exploit_commands();

foreach cmd (keys(cmds)) {
  # feel free to complement this list with useful and/or necessary expressions
  expressions = make_list("system('" + cmds[cmd] + "')",
                            ";" + cmds[cmd]);
  foreach cgi (cgis) {
    cgiArray = split(cgi, sep:" ", keep:FALSE);
    foreach ex (expressions) {
      urls = http_create_exploit_req(cgiArray:cgiArray, ex:ex);
      foreach url (urls) {
        if(http_vuln_check(port:port, url:url, pattern:cmd)) {
          report = http_report_vuln_url(port:port, url:url);
          security_message(port:port, data:report);
          exit(0);
        }
      }
    }
  }
}
exit(99);
