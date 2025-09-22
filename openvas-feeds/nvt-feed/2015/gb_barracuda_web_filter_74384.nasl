# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:barracuda:web_filter";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105287");
  script_version("2024-11-08T15:39:48+0000");
  script_tag(name:"last_modification", value:"2024-11-08 15:39:48 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"creation_date", value:"2015-06-03 16:03:11 +0200 (Wed, 03 Jun 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2015-0961", "CVE-2015-0962");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Barracuda Web Filter < 8.1.0.005 SSL Certificate Multiple Security Bypass Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_barracuda_web_filter_detect.nasl");
  script_mandatory_keys("barracuda_web_filter/installed");

  script_tag(name:"summary", value:"Barracuda Web Filter is prone to multiple security-bypass
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Barracuda Web Filter when SSL Inspection is enabled, uses the
  same root Certification Authority certificate across different customers' installations, which
  makes it easier for remote attackers to conduct man-in-the-middle attacks against SSL sessions by
  leveraging the certificate's trust relationship.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow attackers to perform
  man-in-the-middle attacks or impersonate trusted servers, which will aid in further attacks.");

  script_tag(name:"affected", value:"Barracuda Web Filter versions 7.x and 8.x prior to
  8.1.0.005.");

  script_tag(name:"solution", value:"Update to version 8.1.0.005 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74384");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version =~ "^7\." || version =~ "^8\." ) {
  if( version_is_less( version:version, test_version:"8.1.0.005" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"8.1.0.005" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
