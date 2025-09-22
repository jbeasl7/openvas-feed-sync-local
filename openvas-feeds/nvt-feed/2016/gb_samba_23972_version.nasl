# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108012");
  script_version("2025-03-18T05:38:50+0000");
  script_cve_id("CVE-2007-2447");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-18 05:38:50 +0000 (Tue, 18 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-10-31 12:47:00 +0200 (Mon, 31 Oct 2016)");
  script_name("Samba 3.0.0 <= 3.0.25rc3 MS-RPC Remote Shell Command Execution Vulnerability - Version Check");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Gain a shell remotely");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2007-2447.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121173708/http://www.securityfocus.com/bid/23972");

  script_tag(name:"summary", value:"Samba is prone to a vulnerability that allows attackers to
  execute arbitrary shell commands because the software fails to sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary shell
  commands on an affected system with the privileges of the application.");

  script_tag(name:"affected", value:"Samba versions 3.0.0 through 3.0.25rc3.");

  script_tag(name:"solution", value:"Updates are available. Please see the referenced vendor
  advisory.");

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

if( version_is_less_equal( version:vers, test_version:"3.0.25rc3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See referenced vendor advisory", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
