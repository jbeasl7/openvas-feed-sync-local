# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:option:cloudgate_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808246");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-04 18:38:14 +0530 (Mon, 04 Jul 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Option CloudGate Insecure Direct Object References And XSS Vulnerabilities");

  script_tag(name:"summary", value:"Option CloudGate is prone to cross site scripting and insecure direct object reference authorization bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to bypass authorization and access resource or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The application provides direct access to objects based on user-supplied input.

  - An insufficient validation of user supplied input by API's.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script into user's browser session and also
  to bypass authorization and access resources and functionalities in the system
  directly, for example APIs, files, upload utilities, device settings, etc.");

  script_tag(name:"affected", value:"Option CloudGate CG0192-11897 and probably other models.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40016");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_option_cloudgate_consolidation.nasl");
  script_mandatory_keys("option/cloudgate/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/partials/firewall.html";

if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern: "navigation.firewall' | i18n",
                    extra_check: make_list("firewall.defaultPolicies", "firewall.rebootChanges",
                                           "firewall.staticRouting.editStaticRouting"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
