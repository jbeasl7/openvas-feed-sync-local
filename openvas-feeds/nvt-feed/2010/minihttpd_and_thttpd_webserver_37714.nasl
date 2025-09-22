# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100447");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-13 11:20:27 +0100 (Wed, 13 Jan 2010)");
  script_cve_id("CVE-2009-4490", "CVE-2009-4491");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Acme thttpd and mini_httpd Terminal Escape Sequence in Logs Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37714");
  script_xref(name:"URL", value:"http://www.acme.com/software/mini_httpd/");
  script_xref(name:"URL", value:"http://www.acme.com/software/thttpd/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508830");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("mini_httpd_or_thttpd/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Acme 'thttpd' and 'mini_httpd' are prone to a command-injection
  vulnerability because they fail to adequately sanitize user-supplied input in logfiles.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary commands in
  a terminal.");

  script_tag(name:"affected", value:"This issue affects thttpd 2.25b and mini_httpd 1.19. Other versions
  may also be affected.");

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
banner = http_get_remote_headers(port: port);
if(!banner)exit(0);

if("Server: mini_httpd/" >< banner) {
  version = eregmatch(pattern:"Server: mini_httpd/([0-9.]+)", string: banner);
  if(!isnull(version[1])) {
    if(version_is_less_equal(version: version[1], test_version: "1.19")) {
      security_message(port:port);
      exit(0);
    }
  }
}
else if("Server: thttpd/" >< banner) {
   version = eregmatch(pattern:"Server: thttpd/([0-9.]+[a-z]*)", string: banner);
   if(!isnull(version[1])) {
     if(version_is_less_equal(version: version[1], test_version: "2.25b")) {
       security_message(port:port);
       exit(0);
     }
   }
}

exit(0);
