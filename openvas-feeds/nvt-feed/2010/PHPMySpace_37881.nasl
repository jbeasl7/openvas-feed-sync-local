# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100465");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-25 18:49:48 +0100 (Mon, 25 Jan 2010)");
  script_cve_id("CVE-2010-0377");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHPMySpace Gold 'gid' Parameter SQL Injection Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("PHPMySpace_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpmyspace/detected");

  script_tag(name:"summary", value:"PHPMySpace Gold is prone to an SQL-injection vulnerability because it
  fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"PHPMySpace Gold 8.0 is vulnerable, other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37881");
  script_xref(name:"URL", value:"http://popscript.com/php-scripts/social-network/php-myspace-gold-edition-8-10/prod_180.html");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(!version = get_kb_item(string("www/", port, "/phpMySpace")))
  exit(0);

if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))
  exit(0);

vers = matches[1];

if(vers && "unknown" >!< vers) {
  if(version_is_equal(version: vers, test_version: "8.0")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
