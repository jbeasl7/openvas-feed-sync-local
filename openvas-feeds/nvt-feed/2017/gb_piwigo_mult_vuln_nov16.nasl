# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:piwigo:piwigo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108293");
  script_cve_id("CVE-2016-10513", "CVE-2016-10514");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-11-22 12:59:41 +0100 (Wed, 22 Nov 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-05 21:08:00 +0000 (Sun, 05 Nov 2017)");
  script_name("Piwigo < 2.8.3 Multiple Vulnerabilities (Dec 2016)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_xref(name:"URL", value:"http://piwigo.org/releases/2.8.3");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/547");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/548");

  script_tag(name:"summary", value:"Piwigo is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Check the installed version.");

  script_tag(name:"insight", value:"Piwigo is prone to multiple vulnerabilities:

  - Cross Site Scripting (XSS) (CVE-2016-10513)

  - Security Bypass (CVE-2016-10514)");

  script_tag(name:"impact", value:"An attacker may:

  - inject arbitrary web script or HTML code (CVE-2016-10513)

  - bypass intended access restrictions (CVE-2016-10514).");

  script_tag(name:"affected", value:"Piwigo versions prior to 2.8.3.");

  script_tag(name:"solution", value:"Update to version 2.8.3 or later");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2.8.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.8.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
