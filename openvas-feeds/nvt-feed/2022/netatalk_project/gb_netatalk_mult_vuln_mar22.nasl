# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netatalk:netatalk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113948");
  script_version("2024-03-15T05:06:15+0000");
  script_tag(name:"last_modification", value:"2024-03-15 05:06:15 +0000 (Fri, 15 Mar 2024)");
  script_tag(name:"creation_date", value:"2022-04-25 14:38:33 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-03 18:19:00 +0000 (Mon, 03 Apr 2023)");
  script_cve_id("CVE-2021-31439", "CVE-2022-0194", "CVE-2022-23121", "CVE-2022-23122",
                "CVE-2022-23123", "CVE-2022-23124", "CVE-2022-23125");
  script_name("Netatalk < 3.1.13 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_netatalk_asip_afp_detect.nasl");
  script_mandatory_keys("netatalk/detected");

  script_tag(name:"summary", value:"Netatalk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-0194, CVE-2022-23122, CVE-2022-23125: Stack-based Buffer Overflow

  - CVE-2022-23121: Improper Handling of Exceptional Conditions

  - CVE-2022-23123, CVE-2022-23124: Out-of-bounds Read

  - CVE-2021-31439: Heap-based buffer overflow");

  script_tag(name:"affected", value:"Netatalk prior to version 3.1.13.");

  script_tag(name:"solution", value:"Update to version 3.1.13 or later.");

  script_xref(name:"URL", value:"https://netatalk.io/3.1/ReleaseNotes3.1.13");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"3.1.13" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.1.13" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
