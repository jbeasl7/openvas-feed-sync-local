# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100262");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-26 20:38:31 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("ViewVC < 1.0.9 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("viewvc_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("viewvc/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36035");
  script_xref(name:"URL", value:"http://viewvc.tigris.org/source/browse/viewvc/trunk/CHANGES?rev=HEAD");

  script_tag(name:"summary", value:"ViewVC is prone multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - A cross-site scripting (XSS) vulnerability

  - An unspecified security vulnerability that may allow attackers to print illegal parameter names
  and values");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site and steal
  cookie-based authentication credentials. Other attacks are also possible.");

  script_tag(name:"affected", value:"ViewVC versions prior to 1.0.9 are vulnerable.");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for
  details.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(!version = get_kb_item(string("www/", port, "/viewvc")))
  exit(0);

if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))
  exit(0);

vers = matches[1];

if(vers && "unknown" >!< vers) {
  if(version_is_less(version: vers, test_version: "1.0.9")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
