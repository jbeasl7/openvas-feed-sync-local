# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103283");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-10-05 13:15:09 +0200 (Wed, 05 Oct 2011)");
  script_cve_id("CVE-2011-3585");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-10 17:53:00 +0000 (Fri, 10 Jan 2020)");
  script_name("Samba 'mtab' Lock File Handling Local DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49940");
  script_xref(name:"URL", value:"https://bugzilla.samba.org/show_bug.cgi?id=7179");
  script_xref(name:"URL", value:"http://git.samba.org/?p=cifs-utils.git;a=commitdiff;h=810f7e4e0f2dbcbee0294d9b371071cb08268200");

  script_tag(name:"summary", value:"Samba is prone to a local denial of service (DoS) vulnerability
  that affects the mounting utilities 'mount.cifs' and 'umount.cifs'.");

  script_tag(name:"impact", value:"A local attacker can exploit this issue to cause the mounting
  utilities to abort, resulting in a denial-of-service condition.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
loc = infos["location"];

if( version_is_less_equal( version:vers, test_version:"3.6.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.6.1", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
