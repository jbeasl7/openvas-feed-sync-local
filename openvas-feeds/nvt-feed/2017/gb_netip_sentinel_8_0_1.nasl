# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netiq:sentinel";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140233");
  script_cve_id("CVE-2017-5184", "CVE-2017-5185");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-11-03T05:05:46+0000");

  script_name("Sentinel Server Leakage of Information and Remote Denial of Service Issue");

  script_xref(name:"URL", value:"https://www.netiq.com/support/kb/doc.php?id=7018753");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version/revision is present on the target host.");

  script_tag(name:"solution", value:"Customers should upgrade to Sentinel 8.0.1.");

  script_tag(name:"summary", value:"A vulnerability was discovered in NetIQ Sentinel Server that may allow leakage of information and remote denial of service.");
  script_tag(name:"affected", value:"NetIQ Sentinel 8.0 Sentinel Server.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-19 16:18:00 +0000 (Tue, 19 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-03-31 15:01:13 +0200 (Fri, 31 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_netiq_sentinel_detect.nasl");
  script_mandatory_keys("netiq_sentinel/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version !~ "^8\.0" ) exit( 99 );

if( version_is_less( version:version, test_version:"8.0.1" ) )
{
  report = report_fixed_ver( installed_version:version, fixed_version:"8.0.1" );

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );