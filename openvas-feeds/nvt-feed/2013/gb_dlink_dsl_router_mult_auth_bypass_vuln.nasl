# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:dlink:dsl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803700");
  script_version("2025-06-26T05:40:52+0000");
  script_tag(name:"last_modification", value:"2025-06-26 05:40:52 +0000 (Thu, 26 Jun 2025)");
  script_tag(name:"creation_date", value:"2013-05-21 12:05:19 +0530 (Tue, 21 May 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("D-Link DSL Router Multiple Authentication Bypass Vulnerabilities (May 2013) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dsl_consolidation.nasl");
  script_mandatory_keys("d-link/dsl/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"D-Link DSL Routers are prone to multiple authentication bypass
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The web interface of DSL routers expose several pages
  accessible with no authentication. These pages can be abused to access sensitive information
  concerning the device configuration, including the clear-text password for the administrative
  user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to retrieve the
  administrator password and then access the device with full privileges. This will allow an
  attacker to launch further attacks.");

  script_tag(name:"affected", value:"D-Link DSL Router version BZ_1.06 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://1337day.com/exploit/20789");
  script_xref(name:"URL", value:"http://w00t.pro/2013/05/19/17033");
  script_xref(name:"URL", value:"http://www.allinfosec.com/2013/05/19/web-applications-dsl-router-d-link-bz_1-06-multiple-vulnerabilities");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

url = "/password.cgi";

if (http_vuln_check(port: port, url: url, pattern: "pwdAdmin = '.*",
                    extra_check: make_list("pwdUser = '", ">Access Control -- Passwords<", "Access to your DSL router"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
