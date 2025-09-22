# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dell:insightiq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140146");
  script_version("2024-09-12T07:59:53+0000");
  script_tag(name:"last_modification", value:"2024-09-12 07:59:53 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-02-02 11:06:53 +0100 (Thu, 02 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-2765");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell EMC Isilon InsightIQ Authentication Bypass Vulnerability (Feb 2017)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dell_powerscale_insightiq_http_detect.nasl");
  script_mandatory_keys("dell/insightiq/detected");

  script_tag(name:"summary", value:"Dell EMC Isilon InsightIQ is prone to an authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass authentication
  mechanism and perform unauthorized actions. This may lead to further attacks.");

  script_tag(name:"affected", value:"EMC Isilon InsightIQ versions 4.1.0, 4.0.1, 4.0.0, 3.2.2,
  3.2.1, 3.2.0, 3.1.1, 3.1.0, 3.0.1 and 3.0.0.");

  script_tag(name:"solution", value:"Update to version 4.1.1 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95945");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"4.1.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.1.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
