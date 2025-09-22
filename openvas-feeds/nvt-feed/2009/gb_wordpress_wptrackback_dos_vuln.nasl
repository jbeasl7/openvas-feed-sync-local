# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900968");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3622");
  script_name("WordPress wp-trackback.php Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37088/");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9431");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53884");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2986");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a Denial of Service
  due to high CPU consumption.");

  script_tag(name:"affected", value:"WordPress version prior to 2.8.5 on all platforms.");

  script_tag(name:"insight", value:"An error occurs in wp-trackbacks.php due to improper validation of user
  supplied data passed into 'mb_convert_encoding()' function. This can be
  exploited by sending multiple-source character encodings into the function.");

  script_tag(name:"solution", value:"Upgrade to WordPress version 2.8.5 or later.");

  script_tag(name:"summary", value:"WordPress is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wpPort = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:wpPort))
  exit(0);

if(version_is_less(version:ver, test_version:"2.8.5")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.8.5");
  security_message(port:wpPort, data:report);
  exit(0);
}

exit(99);