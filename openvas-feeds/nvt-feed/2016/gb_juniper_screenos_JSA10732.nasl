# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:juniper:screenos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105605");
  script_cve_id("CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-3195", "CVE-2016-1268");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Multiple Security issues with ScreenOS (JSA10732/JSA10733)");

  script_xref(name:"URL", value:"http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10732&actp=RSS");
  script_xref(name:"URL", value:"http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10733&actp=RSS");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A specially crafted malformed packet received on any interface targeted to the device's administrative web services interface may cause loss of administrative access to the system and can reboot the system causing a complete denial of service.");

  script_tag(name:"solution", value:"Update to ScreenOS 6.3.0r22 or newer");

  script_tag(name:"summary", value:"ScreenOS: Multiple Vulnerabilities in OpenSSL / Malformed SSL/TLS packet causes Denial of Service");
  script_tag(name:"affected", value:"These issues can affect any product or platform running ScreenOS prior to 6.3.0r22");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:20:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-04-15 14:21:00 +0200 (Fri, 15 Apr 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_screenos_version.nasl");
  script_mandatory_keys("ScreenOS/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

display_version = version;

version = str_replace( string:version, find:"r", replace:"." );
version = str_replace( string:version, find:"-", replace:"." );

display_fix = '6.3.0r22';

if( version_is_less( version:version, test_version:'6.3.0.22' ) )
{
  report = report_fixed_ver( installed_version:display_version, fixed_version:display_fix );

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

