# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100384");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-09 12:14:51 +0100 (Wed, 09 Dec 2009)");
  script_cve_id("CVE-2009-4297");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Moodle Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37244");
  script_xref(name:"URL", value:"http://moodle.org/security/");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Moodle/Version");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities including cross-site
request-forgery, security bypass, information-disclosure and SQL-
injection issues.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to bypass certain security
restrictions, gain access to sensitive information, perform
unauthorized actions, compromise the application, access or modify
data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"These issues affect Moodle versions prior to 1.8.11 and 1.9.7.");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(!version = get_kb_item(string("www/", port, "/moodle")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(vers && "unknown" >!< vers) {
  if(vers =~ "^1\.8") {
    if(version_is_less(version: vers, test_version: "1.8.11")) {
      security_message(port:port);
      exit(0);
    }
  } else if(vers =~ "^1\.9") {
    if(version_is_less(version: vers, test_version: "1.9.7")) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(0);
