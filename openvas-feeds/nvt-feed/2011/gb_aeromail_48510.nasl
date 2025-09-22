# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103205");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-17 15:40:19 +0200 (Wed, 17 Aug 2011)");

  script_name("AeroMail Cross Site Request Forgery, HTML Injection and Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48510");
  script_xref(name:"URL", value:"http://www.nicolaas.net/aeromail/index.php?page=index");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_aeromail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("aeromail/detected");

  script_tag(name:"solution", value:"A third party patch is available. Please see the references for
  details.");

  script_tag(name:"summary", value:"AeroMail is prone to multiple remote vulnerabilities, including:

  1. A cross-site scripting vulnerability.

  2. Multiple HTML-injection vulnerabilities.

  3. Multiple cross-site request forgery vulnerabilities.");

  script_tag(name:"impact", value:"The attacker can exploit the cross-site scripting issue to execute
  arbitrary script code in the context of the vulnerable site,
  potentially allowing the attacker to steal cookie-based authentication
  credentials. The attacker may also be perform certain administrative
  functions and delete arbitrary files. Other attacks are also possible.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(vers = get_version_from_kb(port:port,app:"AeroMail")) {
  if(version_is_equal(version: vers, test_version: "2.80")) {
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"Equal to 2.80");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
