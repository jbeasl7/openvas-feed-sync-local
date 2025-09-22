# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:western_digital:my_book_live_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117530");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2018-18472", "CVE-2021-35941");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-07-02 08:35:41 +0000 (Fri, 02 Jul 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-25 10:15:00 +0000 (Fri, 25 Jun 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Western Digital My Book Live End of Life (EOL) Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_wd_mybook_live_http_detect.nasl");
  script_mandatory_keys("western_digital/mybook_live/detected");

  script_xref(name:"URL", value:"https://support-en.wd.com/app/answers/detail/a_id/28740");
  script_xref(name:"URL", value:"https://www.westerndigital.com/support/productsecurity/wdc-21008-recommended-security-measures-wd-mybooklive-wd-mybookliveduo");

  script_tag(name:"summary", value:"The remote Western Digital My Book Live device has reached the
  End of Life (EOL) / End of Updates (EOU) and should not be used anymore.");

  script_tag(name:"insight", value:"At least the following unfixed vulnerabilities exist
  affecting My Book Live and My Book Live Duo (all versions):

  - CVE-2018-18472: root remote command execution vulnerability

  affecting My Book Live (2.x and later) and My Book Live Duo (all versions):

  - CVE-2021-35941: unauthenticated factory reset vulnerability

  - No CVE: remotely exploitable command injection vulnerability when the device has remote access
  enabled");

  script_tag(name:"impact", value:"An EOL / EOU My Book Live device is not receiving any security
  updates from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to
  compromise the security of this host.");

  script_tag(name:"solution", value:"Replace the device by a still supported one.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a My Book Live device which has
  reached the EOL / EOU.");

  exit(0);
}

include("host_details.inc");
include("eol_shared.inc");

if( ! get_app_location( cpe:CPE, nofork:TRUE, skip_port:TRUE ) )
  exit( 0 );

report = eol_build_message( name:"Western Digital My Book Live",
                            cpe:CPE,
                            eol_date:"Received final firmware update in 2015",
                            eol_url:"https://support-en.wd.com/app/answers/detail/a_id/28740",
                            eol_version:"All versions",
                            eol_type:"prod",
                            skip_version:TRUE );
security_message( port:0, data:report );
exit( 0 );
