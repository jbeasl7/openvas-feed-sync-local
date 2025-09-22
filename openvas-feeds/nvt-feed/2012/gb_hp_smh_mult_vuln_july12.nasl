# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802657");
  script_version("2025-01-17T15:39:18+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2011-1944", "CVE-2011-2821", "CVE-2011-2834", "CVE-2011-3379", "CVE-2011-3607",
                "CVE-2011-4078", "CVE-2011-4108", "CVE-2011-4153", "CVE-2011-4317", "CVE-2011-4415",
                "CVE-2011-4576", "CVE-2011-4577", "CVE-2011-4619", "CVE-2011-4885", "CVE-2012-0021",
                "CVE-2012-0027", "CVE-2012-0031", "CVE-2012-0036", "CVE-2012-0053", "CVE-2012-0057",
                "CVE-2012-0830", "CVE-2012-1165", "CVE-2012-1823", "CVE-2012-2012", "CVE-2012-2013",
                "CVE-2012-2014", "CVE-2012-2015", "CVE-2012-2016");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:48:42 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-07-09 15:15:15 +0530 (Mon, 09 Jul 2012)");
  script_name("HP/HPE System Management Homepage (SMH) Multiple Vulnerabilities (HPSBMU02786)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_hp_smh_http_detect.nasl");
  script_mandatory_keys("hp/smh/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49592");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027209");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54218");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=c03360041");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- An unspecified local security vulnerability

  - A denial of service vulnerability

  - An input validation vulnerability

  - A privilege escalation vulnerability

  - An information disclosure vulnerability");

  script_tag(name:"solution", value:"Update to version 7.1.1 or later.");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) is prone to multiple
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain elevated
  privileges, disclose sensitive information, perform unauthorized actions, or cause denial of
  service conditions.");

  script_tag(name:"affected", value:"HP/HPE SMH prior to version 7.1.1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"7.1.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"7.1.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
