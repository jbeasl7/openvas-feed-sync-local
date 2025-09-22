# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15937");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"OSVDB", value:"7977");
  script_name("PunBB IMG Tag Client Side Scripting XSS");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("punBB_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("punBB/installed");

  script_xref(name:"URL", value:"http://www.punbb.org/changelogs/1.0_to_1.0.1.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11850");

  script_tag(name:"solution", value:"Update to PunBB version 1.0.1 or later.");

  script_tag(name:"summary", value:"The remote version of PunBB is vulnerable to cross-site scripting
  flaws because the application does not validate IMG tag.");

  script_tag(name:"impact", value:"With a specially crafted URL, an attacker can cause arbitrary code
  execution within a user's browser, resulting in a loss of integrity.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

install = get_kb_item(string("www/", port, "/punBB"));
if(isnull(install))
  exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (egrep(pattern: "^(0\.|1\.0[^.])",string:ver)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
