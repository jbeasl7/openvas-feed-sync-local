# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:magentocommerce:magento";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108061");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2016-4010");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-07 01:29:00 +0000 (Thu, 07 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-01-30 11:00:00 +0100 (Mon, 30 Jan 2017)");
  script_name("Magento < 2.0.6 RCE Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90724");
  script_xref(name:"URL", value:"http://netanelrub.in/2016/05/17/magento-unauthenticated-remote-code-execution/");

  script_tag(name:"summary", value:"Magento Web E-Commerce Platform is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  execute arbitrary code in the context of the affected application. Failed exploit attempts
  may cause a denial-of-service condition.");

  script_tag(name:"affected", value:"Magento CE and EE before 2.0.6.");

  script_tag(name:"solution", value:"Update to Magento CE or EE 2.0.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"2.0.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.6" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
