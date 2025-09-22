# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13650");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10724");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10725");
  script_cve_id("CVE-2004-0594", "CVE-2004-0595");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"OSVDB", value:"7870");
  script_xref(name:"OSVDB", value:"7871");
  script_name("php < 4.3.8");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("PHP/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Upgrade to PHP 4.3.8");

  script_tag(name:"summary", value:"The remote host is running a version of PHP 4.3 which is older or equal to 4.3.7.

  There is a bug in the remote version of this software which may
  allow an attacker to execute arbitrary code on the remote host if the option
  memory_limit is set. Another bug in the function strip_tags() may allow
  an attacker to bypass content-restrictions when submitting data and may
  lead to cross-site-scripting issues.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
php = http_get_remote_headers(port:port);
if(!php || "PHP" >!< php)
  exit(0);

if(ereg(pattern:"PHP/4\.3\.[0-7][^0-9]", string:php)) {
  security_message(port:port);
  exit(0);
}

exit(99);
