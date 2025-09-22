# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bigtreecms:bigtree_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108143");
  script_version("2024-11-08T15:39:48+0000");
  script_tag(name:"last_modification", value:"2024-11-08 15:39:48 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-04-19 07:57:33 +0200 (Wed, 19 Apr 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-21 15:24:00 +0000 (Fri, 21 Apr 2017)");
  script_cve_id("CVE-2017-7881");
  script_name("BigTree CMS <= 4.2.17 CSRF Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_bigtree_detect.nasl");
  script_mandatory_keys("bigtree_cms/detected");

  script_xref(name:"URL", value:"https://www.cdxy.me/?p=765");
  script_xref(name:"URL", value:"https://github.com/bigtreecms/BigTree-CMS/commit/7761481ac40d83ac29fef42bc6b3c07c86694b56");

  script_tag(name:"summary", value:"BigTree CMS is prone to a cross-site request forgery (CSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"BigTree CMS is prone to a CSRF vulnerability because it relies
  on a substring check for CSRF protection, which allows remote attackers to bypass this check by
  placing the required admin/developer/ URI within a query string in an HTTP Referer header.");

  script_tag(name:"affected", value:"BigTree CMS versions through 4.2.17.");

  script_tag(name:"solution", value:"Update to version 4.2.18 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"4.2.17" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.2.18" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
