# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dedecms:dedecms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170258");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-12-01 15:11:58 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-10 14:24:00 +0000 (Thu, 10 Nov 2022)");

  script_cve_id("CVE-2022-43031");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DedeCMS V6 < 6.1.9 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dedecms_http_detect.nasl");
  script_mandatory_keys("dedecms/detected");

  script_tag(name:"summary", value:"DedeCMS is prone to a cross-site request forgery (CSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The vulnerability allows attackers to arbitrarily add
  administrator accounts and modify admin passwords.");

  script_tag(name:"affected", value:"DedeCMS V6 SP2 prior to version 6.1.9.");

  script_tag(name:"solution", value:"Update to version 6.1.9 or later.");

  script_xref(name:"URL", value:"https://github.com/cai-niao98/Dedecmsv6");
  script_xref(name:"URL", value:"https://github.com/DedeBIZ/DedeV6/releases/tag/6.1.9");
  script_xref(name:"URL", value:"https://github.com/DedeBIZ/DedeV6/commit/9213b0368743edc56890aa2b34be9c066d7fb59b");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];
# nb: There are two distinct lines of the product; making sure we handle the right one
if ( version =~ "^6" ) {
  if ( version_is_less( version:version, test_version:"6.1.9" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"6.1.9", install_path:location );
    security_message( port:port, data:report );
    exit( 0 );
  }
} else {
  # nb: This vulnerability probably does not affect the 5.x versions as V6 is a rewrite of the platform
  exit( 99 );
}

exit( 99 );
