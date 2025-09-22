# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100375");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-03 12:57:42 +0100 (Thu, 03 Dec 2009)");
  script_cve_id("CVE-2009-4786", "CVE-2009-4787", "CVE-2009-4788");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Pligg Cross Site Scripting And Request Forgery Remote Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37185");
  script_xref(name:"URL", value:"http://holisticinfosec.org/content/view/130/45/");
  script_xref(name:"URL", value:"http://www.pligg.com/blog/775/pligg-cms-1-0-3-release/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("pligg_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("pligg/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Pligg is prone to multiple cross-site scripting vulnerabilities and a
  cross-site request-forgery vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to steal cookie-based
  authentication credentials or perform unauthorized actions when
  masquerading as the victim. Other attacks are also possible.");

  script_tag(name:"affected", value:"Versions prior to Pligg 1.0.3 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);
if(!version = get_kb_item(string("www/", port, "/pligg")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(vers && "unknown" >!< vers) {
  if(version_is_less(version: vers, test_version: "1.0.3")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
