# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117401");
  script_version("2025-02-28T05:38:49+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-21551");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2021-05-07 12:27:53 +0000 (Fri, 07 May 2021)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-27 16:14:00 +0000 (Thu, 27 May 2021)");
  script_name("Dell Client Platform 'dbutil Driver' Insufficient Access Control Vulnerability (DSA-2021-088)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  script_tag(name:"summary", value:"The Dell Client Platform 'dbutil Driver' is prone to an
  access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks via WMI if the vulnerable dbutil_2_3.sys file exists on
  the target system. If a file was found, checks via PowerShell, if the sha256 file hash is matching
  the hash of the known vulnerable driver.");

  script_tag(name:"insight", value:"Dell dbutil_2_3.sys driver contains an insufficient access
  control vulnerability which may lead to escalation of privileges, denial of service, or
  information disclosure. Local authenticated user access is required.");

  script_tag(name:"solution", value:"Remove the vulnerable dbutil_2_3.sys file from the target.
  Alternatively apply the updates provided by the vendor in the linked references. Please see
  the references for more details.");

  script_xref(name:"URL", value:"https://www.dell.com/support/kbdoc/en-us/000186019/dsa-2021-088-dell-client-platform-security-update-for-dell-driver-insufficient-access-control-vulnerability");
  script_xref(name:"URL", value:"https://www.dell.com/support/kbdoc/en-us/000186020/additional-information-regarding-dsa-2021-088-dell-driver-insufficient-access-control-vulnerability");
  script_xref(name:"URL", value:"https://labs.sentinelone.com/cve-2021-21551-hundreds-of-millions-of-dell-computers-at-risk-due-to-multiple-bios-driver-privilege-escalation-flaws/");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("list_array_func.inc");
include("powershell_func.inc");

if( wmi_is_file_search_disabled() || is_win_cmd_exec_disabled() || ! defined_func( "win_cmd_exec" ) )
  exit( 0 );

file_list = powershell_wmi_file_search_query( file_name:"dbutil_2_3", file_extension:"sys" );

if( ! file_list || ! is_array( file_list ) )
  exit( 0 );

# From https://www.dell.com/support/kbdoc/en-us/000186020/additional-information-regarding-dsa-2021-088-dell-driver-insufficient-access-control-vulnerability
affected_sha256sums_pattern = "(0296E2CE999E67C76352613A718E11516FE1B0EFC3FFDB8918FC999DD76A73A5|87E38E7AEAAAA96EFE1A74F59FCA8371DE93544B7AF22862EB0E574CEC49C7C3)";
report = 'The vulnerable Dell driver was found based on the following information (Filename:sha256 file hash)\n';

foreach file( file_list ) {

  # nb: Get-Filehash is only available since Windows 10 but that should be o.K. for our purpose.
  # This command returns something like e.g.:
  # Algorithm       Hash                                                                   Path
  # ---------       ----                                                                   ----
  # SHA256          9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08       C:\path\to\dbutil_2_3.sys
  #
  # nb: If the "Path" is too long it will be stripped like C:\path\to\dbutil_...
  cmd = 'Get-Filehash ' + file + ' -Algorithm SHA256';
  result = powershell_cmd( cmd:cmd );
  result = chomp( result );
  if( ! result )
    return;

  if( found = eregmatch( string:result, pattern:affected_sha256sums_pattern, icase:FALSE ) ) {
    VULN = TRUE;
    report += '\n' + file + ":" + found[1];
  }
}

if( VULN ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
