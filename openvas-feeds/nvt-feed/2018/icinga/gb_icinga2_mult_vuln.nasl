# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:icinga:icinga2";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113121");
  script_version("2024-11-15T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-15 05:05:36 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-03-02 11:56:30 +0100 (Fri, 02 Mar 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-6532", "CVE-2018-6533", "CVE-2018-6534", "CVE-2018-6535",
                "CVE-2018-6536", "CVE-2017-16933");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Icinga2 < 2.8.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_icinga2_http_detect.nasl");
  script_mandatory_keys("icinga2/detected");

  script_tag(name:"summary", value:"Icinga2 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Effects of successful exploitation range from password
  disclosure over Denial of Service to an attacker gaining complete control over the target
  system.");

  script_tag(name:"affected", value:"Icinga2 version 2.8.1 and prior.");

  script_tag(name:"solution", value:"Update to version 2.8.2 or later. Please see the references
  for more information.");

  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/pull/5715");
  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/pull/5850");
  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/issues/5991");
  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/pull/6103");
  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/pull/6104");
  script_xref(name:"URL", value:"https://github.com/Icinga/icinga2/issues/5793");
  script_xref(name:"URL", value:"https://www.icinga.com/2018/03/22/icinga-2-8-2-released/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( !version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( version_in_range( version: version, test_version: "2.0.0", test_version2: "2.8.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.2" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
