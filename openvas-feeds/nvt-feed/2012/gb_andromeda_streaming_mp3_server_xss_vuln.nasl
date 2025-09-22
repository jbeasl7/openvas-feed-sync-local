# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802777");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-05-14 13:55:03 +0530 (Mon, 14 May 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Andromeda Streaming MP3 Server <= 1.9.3.6 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Andromeda Streaming MP3 Server is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user supplied
  input passed via 's' parameter to the 'andromeda.php' script, which allows attackers to execute
  arbitrary HTML and script code in the context of an affected application or site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"Andromeda Streaming MP3 Server version 1.9.3.6 PHP (2012) and
  prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/18359");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75497");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/112549/ZSL-2012-5087.txt");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5087.php");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/streams", "/music", "/andromeda", "/mp3", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  url = dir + "/andromeda.php";

  if (http_vuln_check(port: port, url: url, check_header: TRUE, usecache: TRUE,
                      pattern: "<title>andromeda|powered by Andromeda", extra_check: "Andromeda:")) {
    url = url + '?q=s&s="><script>alert(document.cookie);</script>';

    if (http_vuln_check(port: port, url: url, check_header: TRUE,
                       pattern:"><script>alert\(document.cookie\);</script>",
                       extra_check:"powered by Andromeda")) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
