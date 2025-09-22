# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zope:zope";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100779");
  script_version("2023-10-06T05:06:29+0000");
  script_tag(name:"last_modification", value:"2023-10-06 05:06:29 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-09-03 15:15:12 +0200 (Fri, 03 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2010-3198");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zope < 2.10.12, 2.11.x < 2.11.7 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_zope_http_detect.nasl");
  script_mandatory_keys("zope/detected");

  script_tag(name:"summary", value:"Zope is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause the vulnerable
  application to crash, denying service to legitimate users.");

  script_tag(name:"affected", value:"Zope prior to version 2.10.12 and version 2.11.x prior to
  2.11.7.");

  script_tag(name:"solution", value:"Update to version 2.10.12, 2.11.7 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42939");
  script_xref(name:"URL", value:"https://mail.zope.org/pipermail/zope-announce/2010-September/002247.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less(version: version, test_version: "2.10.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.10.12", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "2.11", test_version_up: "2.11.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.11.7", install_path: location );
  security_message( data: report, port: port );
  exit(0);
}

exit(99);
