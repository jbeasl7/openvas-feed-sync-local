# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900698");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2608");
  script_name("PHP Address Book Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35590");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35511");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9023");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_address_book_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("PHP-Address-Book/installed");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause SQL Injection attack, gain
  sensitive information about the database used by the web application.");

  script_tag(name:"affected", value:"PHP Address Book version 4.0.x");

  script_tag(name:"insight", value:"The flaw is due to improper sanitization of user supplied input passed to the
  'id' parameter in view.php, edit.php, and delete.php, and to the 'alphabet'
  parameter in index.php before being used in SQL queries.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to PHP Address Book version 5.7.2 or later.");

  script_tag(name:"summary", value:"PHP Address Book is prone to an SQL injection (SQLi) vulnerability.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

phpPort = http_get_port(default:80);

phpVer = get_kb_item("www/"+ phpPort + "/PHP-Address-Book");
if(!phpVer)
  exit(0);

ver = eregmatch(pattern:"^(.+) under (/.*)$", string:phpVer);
if(ver[1] =~ "^4\.0"){
  security_message(phpPort);
}
