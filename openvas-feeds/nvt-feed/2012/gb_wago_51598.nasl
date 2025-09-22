# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:wago:";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103396");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-01-23 15:14:54 +0100 (Mon, 23 Jan 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("WAGO Multiple Remote Vulnerabilities (Jan 2012) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wago_plc_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("wago_plc/http/detected");
  script_require_ports("Services/www", 80);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"WAGO devices are prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - A security bypass vulnerability

  - Multiple information disclosure vulnerabilities

  - A cross-site request forgery (CSRF) vulnerability");

  script_tag(name:"impact", value:"Successful attacks can allow an attacker to obtain sensitive
  information, bypass certain security restrictions, and perform unauthorized administrative
  actions.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.cisa.gov/uscert/ics/alerts/ICS-ALERT-12-020-07A");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51598");
  script_xref(name:"URL", value:"http://dsecrg.com/pages/vul/show.php?id=401");
  script_xref(name:"URL", value:"http://dsecrg.com/pages/vul/show.php?id=402");
  script_xref(name:"URL", value:"http://dsecrg.com/pages/vul/show.php?id=403");
  script_xref(name:"URL", value:"http://dsecrg.com/pages/vul/show.php?id=404");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www", first_cpe_only: TRUE))
  exit(0);

port = infos["port"];

host = http_host_name(port:port);

default_credentials = make_list("admin:wago", "user:user", "guest:guest");

foreach credential(default_credentials) {

  userpass64 = base64(str:credential);

  url = "/webserv/cplcfg/security.ssi";

  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Authorization: Basic ", userpass64, "\r\n",
               "\r\n");
  buf = http_keepalive_send_recv(port:port, data:req);

  if("<caption>Webserver Security" >< buf && "Webserver and FTP User configuration" >< buf) {
    report = 'It was possible to login with the following credentials\n\nURL:User:Password\n\n' + url +
             ":" + credential;
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
