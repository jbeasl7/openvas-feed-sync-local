# SPDX-FileCopyrightText: 2001 Alert4Web.com
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zope:zope";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10777");
  script_version("2023-10-06T05:06:29+0000");
  script_tag(name:"last_modification", value:"2023-10-06 05:06:29 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2001-0567");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zope < 2.3.3 ZClass Permission Mapping Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2001 Alert4Web.com");
  script_family("Web Servers");
  script_dependencies("gb_zope_http_detect.nasl");
  script_mandatory_keys("zope/detected");

  script_tag(name:"summary", value:"Zope is prone to a permission mapping vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Any user can visit a ZClass declaration and change the ZClass
  permission mappings for methods and other objects defined within the ZClass, possibly allowing
  for unauthorized access within the Zope instance.");

  script_tag(name:"solution", value:"Update to version 2.3.3 or later.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( version_is_less( version: version, test_version: "2.3.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.3.3" );
  security_message(port: port, data: report );
  exit( 0 );
}

exit( 99 );
