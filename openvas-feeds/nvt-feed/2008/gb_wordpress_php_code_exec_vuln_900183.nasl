# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900183");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5695");
  script_name("WordPress 'wp-admin/options.php' RCE Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/28789");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27633");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5066");
  script_xref(name:"URL", value:"http://mu.wordpress.org/forums/topic.php?id=7534&page&replies=1");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code by
  uploading a PHP script and adding this script pathname to active_plugins.");

  script_tag(name:"affected", value:"WordPress, WordPress prior to 2.3.3
  WordPress, WordPress MU prior to 1.3.2.");

  script_tag(name:"insight", value:"The flaw is due to error under 'wp-admin/options.php' file. These
  can be exploited by using valid user credentials with 'manage_options' and upload_files capabilities.");

  script_tag(name:"solution", value:"Upgrade to version 1.3.2 and 2.3.3 or later.");

  script_tag(name:"summary", value:"WordPress is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wpPort = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:wpPort))
  exit(0);

if(version_is_less_equal(version:ver, test_version:"2.3.2")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.3.2");
  security_message(port:wpPort, data:report);
  exit(0);
}

exit(99);