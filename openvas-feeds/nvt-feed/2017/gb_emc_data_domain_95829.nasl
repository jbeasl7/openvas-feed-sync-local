# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:emc:data_domain_os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140144");
  script_cve_id("CVE-2016-8216");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_version("2025-09-10T05:38:24+0000");

  script_name("EMC Data Domain OS Local Command Injection Vulnerability (ESA-2016-160)");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95829");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2017/Jan/att-79/ESA-2016-160.txt");

  script_tag(name:"impact", value:"A local attacker can exploit this issue to bypass the Data Domain
  restricted shell (ddsh) to gain shell access and execute arbitrary commands with root
  privileges.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The following EMC Data Domain OS (DD OS) release contains a
  resolution to this vulnerability:

  - EMC Data Domain DD OS 5.7 family version 5.7.2.10 and later

  - EMC Data Domain DD OS 5.6 family version 5.6.2.0  and later

  - EMC Data Domain DD OS 5.5 family version 5.5.5.0 and later");

  script_tag(name:"summary", value:"EMC Data Domain OS is prone to a local command injection
  vulnerability.");

  script_tag(name:"affected", value:"- EMC Data Domain OS (DD OS) 5.4 all versions

  - EMC Data Domain OS (DD OS) 5.5 family all versions prior to 5.5.5.0

  - EMC Data Domain OS (DD OS) 5.6 family all versions prior to 5.6.2.0

  - EMC Data Domain OS (DD OS) 5.7 family all versions prior to 5.7.2.10");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-23 18:21:00 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2017-02-01 14:29:24 +0100 (Wed, 01 Feb 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_emc_data_domain_consolidation.nasl");
  script_mandatory_keys("emc/data_domain/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version =~ "^5\.5" )
  fix = "5.5.5.0";

else if( version =~ "^5\.6" )
  fix = "5.6.2.0";

else if( version =~ "^5\.7" )
  fix = "5.7.2.10";

if( ! fix ) exit( 99 );

if( version_is_less( version:version, test_version:fix ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
