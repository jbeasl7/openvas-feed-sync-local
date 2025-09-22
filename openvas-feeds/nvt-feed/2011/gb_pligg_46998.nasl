# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103139");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-04-01 13:32:12 +0200 (Fri, 01 Apr 2011)");

  script_name("Pligg CMS Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46998");
  script_xref(name:"URL", value:"http://www.pligg.com/");
  script_xref(name:"URL", value:"http://forums.pligg.com/current-version/23041-pligg-content-management-system-1-1-4-a.html");
  script_xref(name:"URL", value:"http://h.ackack.net/the-pligg-cms-0dayset-1.html");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("pligg_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("pligg/detected");

  script_tag(name:"solution", value:"The vendor has released a fix. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Pligg CMS is prone to multiple security vulnerabilities because it
  fails to properly sanitize user-supplied input. These vulnerabilities
  include a local file-include vulnerability, a security-bypass
  vulnerability, and an authentication-bypass vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to view and execute arbitrary local
  files in the context of the webserver process, bypass security-restrictions, and perform unauthorized actions.");

  script_tag(name:"affected", value:"Versions prior to Pligg CMS 1.1.4 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(ver = get_version_from_kb(port:port, app:"pligg"))
{
  if(version_is_less(version:ver, test_version:"1.1.4")){
    report = report_fixed_ver(installed_version:ver, fixed_version:"1.1.4");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
