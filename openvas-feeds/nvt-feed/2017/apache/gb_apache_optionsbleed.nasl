# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112048");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-09-20 12:53:35 +0200 (Wed, 20 Sep 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");
  script_cve_id("CVE-2017-9798");
  script_name("Apache HTTP Server OPTIONS Memory Leak Vulnerability (Optionsbleed) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/09/18/2");
  script_xref(name:"URL", value:"https://blog.fuzzing-project.org/60-Optionsbleed-HTTP-OPTIONS-method-can-leak-Apaches-server-memory.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100872");
  script_xref(name:"URL", value:"https://archive.apache.org/dist/httpd/patches/apply_to_2.2.34/");
  script_xref(name:"URL", value:"https://www.apache.org/dist/httpd/CHANGES_2.4.28");

  script_tag(name:"summary", value:"Apache HTTP Server allows remote attackers to read
  secret data from process memory if the Limit directive can be set in a user's .htaccess
  file, or if httpd.conf has certain misconfigurations, aka Optionsbleed.");

  script_tag(name:"vuldetect", value:"Checks for a corrupted Allow header that is being
  constructed in response to HTTP OPTIONS requests.");

  script_tag(name:"insight", value:"Optionsbleed is a use after free error in the Apache
  HTTP Server that causes a corrupted Allow header to be constructed in response to HTTP
  OPTIONS requests. This can leak pieces of arbitrary memory from the server process that
  may contain secrets. The memory pieces change after multiple requests, so for a vulnerable
  host an arbitrary number of memory chunks can be leaked.

  The bug appears if a webmaster tries to use the 'Limit' directive with an invalid HTTP
  method.

  Example .htaccess:

  <Limit abcxyz>
  </Limit>");

  script_tag(name:"impact", value:"The successful exploitation allows the attacker to read
  chunks of the host's memory.");

  script_tag(name:"affected", value:"Apache HTTP Server 2.2.x versions up to 2.2.34 and
  2.4.x below 2.4.28.");

  script_tag(name:"solution", value:"Update to Apache HTTP Server 2.4.28. For Apache HTTP
  Server running version 2.2.34 apply the patch linked in the references.

  As a workaround the usage of .htaccess should be disabled completely via the
  'AllowOverride None' directive within the webservers configuration. Furthermore all
  <Limit> statements within the webserver configuration needs to be verified for
  invalid HTTP methods.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

#TODO: Once this vulnerability got older we might want to consider to limit the amounts of directories to check here
foreach dir(make_list_unique("/", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  url = dir + "/";

  req = 'OPTIONS ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Connection: Close\r\n\r\n';

  for(i = 0; i <= 100; i++) {
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if(!res || res !~ "^HTTP/1\.[01] [0-9]{3}")
      continue;

    if(res =~ "^HTTP/1\.[01] 405")
      break; # We don't need to continue in this inner loop if the OPTIONS method is disabled.

    if(allow = egrep(string:res, pattern:"^Allow\s*:.+", icase:TRUE)) {
      # Examples:
      # Allow: POST,OPTIONS,,HEAD,:09:44 GMT
      # Allow: ,GET,HEAD,POST,OPTIONS
      # Allow: HEAD,,HEAD,POST,,HEAD,TRACE
      # Allow: POST,OPTIONS,GET,HEAD,,HEAD,write.c>
      if(vuln = eregmatch(pattern:"(,{2,}|,\W+,|^\w+:[\s]{0,},|[0-9])", string:allow)) {
        report = "The remote service might leak data/memory via the 'Allow' header.";
        report += '\n\nRequest:\n' + req + '\nResponse:\n' + res;
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
