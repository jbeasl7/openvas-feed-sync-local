# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:netscaler";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105272");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-12 13:10:00 +0200 (Tue, 12 May 2015)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-2840", "CVE-2015-2838", "CVE-2015-2839");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix NetScaler < 10.5 build 52.3nc Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_citrix_netscaler_consolidation.nasl");
  script_mandatory_keys("citrix/netscaler/detected");

  script_tag(name:"summary", value:"Citrix NetScaler VPX is prone to multiple cross-site scripting
  vulnerabilities and a cross-site request forgery (CSRF) vulnerability because the application
  fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2015-2840: Cross-site scripting (XSS) vulnerability in help/rt/large_search.html allows
  remote attackers to inject arbitrary web script or HTML via the searchQuery parameter.

  - CVE-2015-2839: The Nitro API uses an incorrect Content-Type when returning an error message,
  which allows remote attackers to conduct cross-site scripting (XSS) attacks via the file_name
  JSON member in params/xen_hotfix/0 to nitro/v1/config/xen_hotfix.

  - CVE-2015-2838: Cross-site request forgery (CSRF) vulnerability in Nitro API allows remote
  attackers to hijack the authentication of administrators for requests that execute arbitrary
  commands as nsroot via shell metacharacters in the file_name JSON member in params/xen_hotfix/0
  to nitro/v1/config/xen_hotfix.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may help
  the attacker steal cookie-based authenticationcredentials and launch other attacks.");

  script_tag(name:"affected", value:"Citrix NetScaler prior to version 10.5 build 52.3nc.");

  script_tag(name:"solution", value:"Update to 10.5 build 52.3nc or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73342");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork: TRUE ) )
  exit( 0 );

if( vers !~ '^10\\.5' )
  exit( 99 );

if( version_is_less( version:vers, test_version:"10.5.52.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.5 build 52.3" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
