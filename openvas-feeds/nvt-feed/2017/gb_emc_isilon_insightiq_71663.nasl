# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dell:insightiq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140135");
  script_version("2024-09-12T07:59:53+0000");
  script_tag(name:"last_modification", value:"2024-09-12 07:59:53 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-01-31 12:44:39 +0100 (Tue, 31 Jan 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-4628");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell EMC Isilon InsightIQ <= 3.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dell_powerscale_insightiq_http_detect.nasl");
  script_mandatory_keys("dell/insightiq/detected");

  script_tag(name:"summary", value:"Dell EMC Isilon InsightIQ is prone to an unspecified cross-site
  scripting (XSS) vulnerability because it fails to sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code  in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Dell EMC Isilon InsightIQ prior to version 3.1.");

  script_tag(name:"solution", value:"Update to version 3.1 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71663");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"3.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
