# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100239");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-22 19:53:45 +0200 (Wed, 22 Jul 2009)");
  script_cve_id("CVE-2009-2851");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress Comment Author URI Cross-Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the references
  for details.");

  script_tag(name:"summary", value:"WordPress is prone to a cross-site scripting vulnerability because the
  application fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may help the attacker
  steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Versions prior to WordPress 2.8.2 are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35755");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=278492");
  script_xref(name:"URL", value:"http://wordpress.org/development/2009/07/wordpress-2-8-2/");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version: vers, test_version: "2.8.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.8.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);