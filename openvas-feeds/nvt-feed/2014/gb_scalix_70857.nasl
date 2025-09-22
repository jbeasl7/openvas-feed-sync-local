# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:scalix:scalix";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105103");
  script_cve_id("CVE-2014-9352", "CVE-2014-9360");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_version("2025-01-21T05:37:33+0000");

  script_name("Scalix Web Access <= 11.4.6.12377, 12.x <= 12.2.0.14697 XXE and XSS Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70857");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70859");

  script_tag(name:"impact", value:"Attackers can exploit the XML External Entity Injection to obtain
  potentially sensitive information. This may lead to further attacks. An attacker may leverage the
  Cross Site Scripting issue to execute arbitrary script code in the browser of an unsuspecting user
  in the context of the affected site. This may allow the attacker to steal cookie-based
  authentication credentials and launch other attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Scalix Web Access is prone to an XML external entity (XXE)
  injection and to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"affected", value:"Scalix Web Access versions 11.4.6.12377 and 12.2.0.14697 are
  vulnerable. Older versions might be affected as well.");

  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-11-03 14:30:39 +0100 (Mon, 03 Nov 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_scalix_detect.nasl");
  script_mandatory_keys("scalix/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"12.0", test_version2:"12.2.0.14697" ) ||
    version_is_less_equal( version:vers, test_version:"11.4.6.12377" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"Contact vendor" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
