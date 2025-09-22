# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803709");
  script_version("2023-06-22T10:34:15+0000");
  script_cve_id("CVE-2012-0744");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2013-06-03 17:40:28 +0530 (Mon, 03 Jun 2013)");
  script_name("IBM Rational ClearQuest Multiple Information Disclosure Vulnerabilities");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74671");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54222");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21606317");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21599361");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain potentially
  sensitive information.");
  script_tag(name:"affected", value:"IBM Rational ClearQuest 7.1.x to 7.1.2.7 and 8.x to 8.0.0.3");
  script_tag(name:"insight", value:"The flaws are due to improper access controls on certain post-installation
  sample scripts. By sending a direct request, an attacker could obtain system
  paths, product versions, and other sensitive information.");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"summary", value:"IBM Rational ClearQuest is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

res = http_get_cache(item:"/cqweb/login", port:port);

if(">Rational<" >< res && "Welcome to Rational ClearQuest Web" >< res) {
  res = http_get_cache(item:"/cqweb/j_security_check", port:port);

  if(res =~ "^HTTP/1\.[01] 200" && res !~ "^HTTP/1\.[01] 404" &&
     ">Object not found!<" >!< res) {
    security_message(port:port);
    exit(0);
  }
}
