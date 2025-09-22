# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140018");
  script_version("2024-03-01T14:37:10+0000");
  script_cve_id("CVE-2016-8870", "CVE-2016-8869", "CVE-2016-9081");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-07 19:15:00 +0000 (Mon, 07 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-10-25 17:01:05 +0200 (Tue, 25 Oct 2016)");

  script_name("Joomla Core < 3.6.4 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The remote Joomla installation is prone to three critical security
vulnerabilities.

  1. Inadequate checks allows for users to register on a site when registration has been disabled.

  2. Incorrect use of unfiltered data allows for users to register on a site with elevated privileges.

  3. Incorrect use of unfiltered data allows for existing user accounts to be modified to include
  resetting their username, password, and user group assignments.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to inadequate filtering of request data.");

  script_tag(name:"affected", value:"Joomla core versions 3.4.4 through 3.6.3");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.6.4 or later");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.joomla.org/announcements/release-news/5678-joomla-3-6-4-released.html");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! ver = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:ver, test_version:"3.4.4", test_version2:"3.6.3" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"3.6.4" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
