# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15639");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1424", "CVE-2004-1425", "CVE-2004-2232");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11608");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11691");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12120");
  script_xref(name:"OSVDB", value:"11427");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Moodle SQL injection flaws");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Moodle/Version");

  script_tag(name:"solution", value:"Upgrade to Moodle 1.4.3 or later.");

  script_tag(name:"summary", value:"The remote version of Moodle is vulnerable to a SQL
  injection issue in 'glossary' module due to a lack of user input sanitization.");

  script_tag(name:"affected", value:"Moodle prior to version 1.4.3.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

install = get_kb_item(string("www/", port, "/moodle"));
if (isnull(install))
  exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^(0\..*|1\.([0-4][^0-9]?|[0-4]\.[012][^0-9]?))$") {
    security_message(port);
    exit(0);
  }
}
