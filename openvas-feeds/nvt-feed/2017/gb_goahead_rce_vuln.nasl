# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:embedthis:goahead";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140609");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-12-19 08:55:23 +0700 (Tue, 19 Dec 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 16:51:59 +0000 (Wed, 24 Jul 2024)");

  script_cve_id("CVE-2017-17562");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Embedthis GoAhead < 3.6.5 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_embedthis_goahead_http_detect.nasl");
  script_mandatory_keys("embedthis/goahead/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Embedthis GoAhead is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple HTTP POST requests and checks the
  responses.");

  script_tag(name:"insight", value:"Embedthis GoAhead allows remote code execution if CGI is
  enabled and a CGI program is dynamically linked. This is a result of initializing the environment
  of forked CGI scripts using untrusted HTTP request parameters in the cgiHandler function in
  cgi.c. When combined with the glibc dynamic linker, this behaviour can be abused for remote code
  execution using special parameter names such as LD_PRELOAD. An attacker can POST their shared
  object payload in the body of the request, and reference it using /proc/self/fd/0.");

  script_tag(name:"impact", value:"An unauthenticated attacker may execute arbitrary code.");

  script_tag(name:"affected", value:"Embedthis GoAhead versions prior to 3.6.5.");

  script_tag(name:"solution", value:"Updated to version 3.6.5 or later. As a migitation step
  disable CGI support.");

  script_xref(name:"URL", value:"https://www.elttam.com/blog/goahead/");
  script_xref(name:"URL", value:"https://github.com/elttam/publications/tree/master/writeups/CVE-2017-17562");
  script_xref(name:"URL", value:"https://web.archive.org/web/20220924090958/https://github.com/embedthis/goahead/issues/249");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43360/");
  script_xref(name:"URL", value:"https://github.com/1337g/CVE-2017-17562/blob/master/CVE-2017-17562.py");
  script_xref(name:"URL", value:"https://github.com/ivanitlearning/CVE-2017-17562");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

# nb: from https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/goahead_ldpreload.rb
cgi_dirs = make_list("/", "/cgi-bin/", "/cgi/");

endpoints = make_list("admin", "apply", "non-CA-rev", "checkCookie", "check_user",
                      "chn/liveView", "cht/liveView", "cnswebserver", "config",
                      "configure/set_link_neg", "configure/swports_adjust", "eng/liveView",
                      "firmware", "getCheckCode", "get_status", "getmac", "getparam",
                      "guest/Login", "home", "htmlmgr", "index", "index/login", "jscript",
                      "kvm", "liveView", "login", "login.asp", "login/login", "login/login-page",
                      "login_mgr", "luci", "main", "main-cgi", "manage/login", "menu",
                      "mlogin", "netbinary", "nobody/Captcha", "nobody/VerifyCode", "normal_userLogin",
                      "otgw", "page", "rulectl", "service", "set_new_config", "sl_webviewer",
                      "ssi", "status", "sysconf", "systemutil", "t/out", "top", "unauth", "upload",
                      "variable", "wanstatu", "webcm", "webmain", "webproc", "webscr", "webviewLogin",
                      "webviewLogin_m64", "webviewer", "welcome", "cgitest");

exts = make_list("", ".cgi");

foreach cgi_dir (cgi_dirs) {
  foreach endpoint (endpoints) {
    foreach ext (exts) {
      url = cgi_dir + endpoint + ext + "?LD_DEBUG=help";

      req = http_post(port: port, item: url, data: "");
      res = http_keepalive_send_recv(port: port, data: req);

      if (res =~ "^HTTP/1\.[01] 200" &&
           # nb: Spaces in the first string are expected / on purpose...
           (" LD_DEBUG_OUTPUT " >< res ||
            "valid options for the ld_debug environment variable are:" >< res)
         ) {
        report = "A HTTP POST request to " + http_report_vuln_url(port: port, url: url, url_only: TRUE) +
                 ' returned the following response:\n\n' + chomp(res);
        security_message(port: port, data: report);
        exit(0);
      }
    }
  }
}

exit(0);
