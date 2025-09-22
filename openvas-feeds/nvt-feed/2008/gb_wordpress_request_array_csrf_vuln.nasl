# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800140");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2008-5113");
  script_name("WordPress _REQUEST array CSRF Vulnerability");

  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2008/11/14/1");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=504771");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected");

  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary script code
  and can cause denial of service condition.");

  script_tag(name:"affected", value:"WordPress 2.6.3 and earlier.");

  script_tag(name:"insight", value:"The flaw is due to incorrect usage of _REQUEST super global array,
  which leads to cross site request forgery (CSRF) attacks via crafted cookies.");

  script_tag(name:"summary", value:"WordPress is prone to cross-site request forgery (CSRF)
  vulnerabilities.");

  script_tag(name:"solution", value:"Update to WordPress version 2.9.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!ver = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less_equal(version:ver, test_version:"2.6.3")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.9.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
