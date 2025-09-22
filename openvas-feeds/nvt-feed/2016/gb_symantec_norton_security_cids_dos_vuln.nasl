# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:norton_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808624");
  script_version("2025-03-07T05:38:18+0000");
  script_cve_id("CVE-2016-5308");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-03-07 05:38:18 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-05 16:24:00 +0000 (Mon, 05 Mar 2018)");
  script_tag(name:"creation_date", value:"2016-10-07 13:20:51 +0530 (Fri, 07 Oct 2016)");
  script_tag(name:"qod_type", value:"registry");

  script_name("Symantec Norton Security 'CIDS' Driver < 15.1.2 DoS Vulnerability");

  script_tag(name:"summary", value:"Symantec Norton Security is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the client intrusion detection system
  (CIDS) driver is improperly handling a malformed PE executable file.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial
  of service (memory corruption and system crash).");

  script_tag(name:"affected", value:"Symantec Norton Security CIDS Drivers prior to version
  15.1.2.");

  script_tag(name:"solution", value:"Update Symantec Norton Security through LiveUpdate.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160707_01");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91608");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_symantec_norton_security_detect.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Symantec/Norton/Security/Ver");
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("powershell_func.inc");
include("list_array_func.inc");

if( ! get_app_version( cpe:CPE ) )
  exit( 0 );

if( wmi_is_file_search_disabled() || is_win_cmd_exec_disabled() )
  exit( 0 );

# TODO: Limit to a possible known common path, maybe from the Detection-VT?
fileList = powershell_wmi_file_search_version_query( file_name:"IDSvix86", file_extension:"sys" );

if( ! fileList || ! is_array( fileList ) ) {
  exit( 0 );
}

foreach filePath( keys( fileList ) ) {

  vers = fileList[filePath];

  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ) ) {

    if( version_is_less( version:version[1], test_version:"15.1.2" ) ) {
      report = report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"15.1.2" );
      security_message( port:0, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
