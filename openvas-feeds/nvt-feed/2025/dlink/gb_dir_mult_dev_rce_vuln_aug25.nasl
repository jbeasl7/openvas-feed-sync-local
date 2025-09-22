# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125315");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-12 12:42:37 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2018-25115");

  script_name("D-Link Multiple DIR Devices RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"Multiple D-Link DIR devices are prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"A vulnerability in the service.cgi endpoint that allows remote
  attackers to execute arbitrary system commands without authentication. The flaw stems from improper
  input handling in the EVENT=CHECKFW parameter, which is passed directly to the system shell without
  sanitization. A crafted HTTP POST request can inject commands that are executed with root
  privileges, resulting in full device compromise. These router models are no longer supported at
  the time of assignment and affected version ranges may vary.");

  script_tag(name:"affected", value:"D-Link DIR-110, DIR-412, DIR-600, DIR-610, DIR-615, DIR-645 and
  DIR-815 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that all devices reached their End-of-Support date prior to May 2024,
  are no longer supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://github.com/Cr0n1c/dlink_shell_poc/blob/master/dlink_auth_rce");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");
  script_xref(name:"URL", value:"https://support.dlink.com/EndOfLifePolicy.aspx");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43496");
  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/dlink-dir-rce-service-cgi");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10456");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10457");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10221");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10327");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10296");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10301");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/security/publication.aspx?name=SAP10434");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:dlink:dir-110_firmware",
                      "cpe:/o:dlink:dir-412_firmware",
                      "cpe:/o:dlink:dir-600_firmware",
                      "cpe:/o:dlink:dir-610_firmware",
                      "cpe:/o:dlink:dir-615_firmware",
                      "cpe:/o:dlink:dir-645_firmware",
                      "cpe:/o:dlink:dir-815_firmware" );

if( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

version = infos["version"];

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );
