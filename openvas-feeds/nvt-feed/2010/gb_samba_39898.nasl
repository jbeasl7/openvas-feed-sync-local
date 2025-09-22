# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100623");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-05-04 19:30:07 +0200 (Tue, 04 May 2010)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-07 19:54:00 +0000 (Thu, 07 Nov 2019)");
  script_cve_id("CVE-2010-0747");
  script_name("Samba 'mount.cifs' Utility Symlink Attack Local Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39898");

  script_tag(name:"summary", value:"Samba is prone to a local privilege escalation vulnerability in the
  'mount.cifs' utility.");

  script_tag(name:"impact", value:"Local attackers can exploit this issue to gain elevated privileges on
  affected computers.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

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

if( version_in_range( version:vers, test_version:"3.4", test_version2: "3.4.7" ) ||
    version_in_range( version:vers, test_version:"3.3", test_version2: "3.3.12" ) ||
    version_in_range( version:vers, test_version:"3.0", test_version2: "3.0.37" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.38/3.3.13/3.4.8", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
