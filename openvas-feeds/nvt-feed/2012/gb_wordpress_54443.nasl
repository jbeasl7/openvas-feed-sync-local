# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103520");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("WordPress Paid Memberships Pro Plugin 'memberslist-csv.php' Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54443");
  script_xref(name:"URL", value:"http://www.paidmembershipspro.com/2012/07/important-security-update-1-5/");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-16 12:51:36 +0200 (Mon, 16 Jul 2012)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");
  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
information.");
  script_tag(name:"summary", value:"The Paid Memberships Pro plugin for WordPress is prone to an information-
disclosure vulnerability because it fails to sufficiently validate user-
supplied data.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to obtain sensitive information
that may aid in further attacks.");

  script_tag(name:"affected", value:"Paid Memberships Pro 1.4.7 is vulnerable, other versions may also
be affected.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + '/wp-content/plugins/paid-memberships-pro/adminpages/memberslist-csv.php';

if(http_vuln_check(port:port, url:url, pattern:"username", extra_check:make_list("zipcode", "address1", "firstname"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
