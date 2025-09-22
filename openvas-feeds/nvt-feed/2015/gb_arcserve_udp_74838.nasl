# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:arcserve:arcserve_unified_data_protection";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105295");
  script_version("2024-07-17T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-06-11 17:46:01 +0200 (Thu, 11 Jun 2015)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:58:57 +0000 (Tue, 16 Jul 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  script_cve_id("CVE-2015-4069", "CVE-2015-4068");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Arcserve Unified Data Protection (UDP) < 5.0 Update 4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_arcserve_udp_http_detect.nasl");
  script_mandatory_keys("arcserve/udp/detected");

  script_tag(name:"summary", value:"Arcserve Unified Data Protection (UDP) is prone to multiple
  information disclosure vulnerabilities and multiple directory traversal vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to obtain sensitive
  information that may lead to further attacks.");

  script_tag(name:"affected", value:"Arcserve UDP prior to version 5.0 Update 4.");

  script_tag(name:"solution", value:"Update to version 5.0 Update 4 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74838");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74845");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_greater( version:vers, test_version:"5.0" ) )
  exit( 99 );

if( version_is_less( version:vers, test_version:"5.0" ) )
  vuln = TRUE;

if( ! vuln ) {
  build = get_kb_item("arcserve/udp/build");
  type = get_kb_item("arcserve/udp/soap_type");
  if( type == "linux" ) {
    if( build ) {
      if( version_is_less( version:build, test_version:"3230.1" ) )
        vuln = TRUE;
    }
  }
  else if( type == "windows" ) {
    update = get_kb_item("arcserve/udp/update");
    if( ! update || int( update ) < 4 )
      vuln = TRUE;
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, installed_build:build, installed_patch:update,
                             fixed_version:"5.0", fixed_build:"3230.1", fixed_patch:"4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
