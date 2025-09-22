# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90028");
  script_version("2023-09-15T05:06:15+0000");
  script_tag(name:"last_modification", value:"2023-09-15 05:06:15 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2008-09-06 20:50:27 +0200 (Sat, 06 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-1105");
  script_name("Samba 3.0.0 <= 3.0.29 Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"solution", value:"All Samba users should upgrade to the latest version.");

  script_tag(name:"summary", value:"The remote host is affected by the vulnerabilities described in
  CVE-2008-1105.");

  script_tag(name:"impact", value:"CVE-2008-1105: Heap-based buffer overflow in the receive_smb_raw function
  in util/sock.c in Samba 3.0.0 through 3.0.29 allows remote attackers to execute arbitrary code via a crafted SMB response.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];

if( ! port )
  path = infos["location"];

if( version_in_range( version:vers, test_version:"3.0.0", test_version2:"3.0.29" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"N/A", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
