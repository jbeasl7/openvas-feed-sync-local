# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113161");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-04-19 12:37:00 +0200 (Thu, 19 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-22 16:20:00 +0000 (Tue, 22 May 2018)");

  script_cve_id("CVE-2018-10070");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS 6.41.4 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"The script checks if the target is a vulnerable device
  running a vulnerable firmware version.");

  script_tag(name:"insight", value:"A vulnerability could allow an unauthenticated remote attacker
  to exhaust all available CPU and all available RAM by sending a crafted FTP request on port 21
  that begins with many '\0' characters, preventing the affected router from accepting new FTP
  connections. The router will reboot after 10 minutes, logging a
  'router was rebooted without proper shutdown' message.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to effectively
  block access to the target host for an arbitrary timespan.");

  script_tag(name:"affected", value:"MikroTik RouterOS through version 6.41.4.");

  script_tag(name:"solution", value:"Update to version 6.42 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/147183/MikroTik-6.41.4-Denial-Of-Service.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

if( version_is_less_equal( version: version, test_version: "6.41.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.42" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
