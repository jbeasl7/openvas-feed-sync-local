# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:encryption_management_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105553");
  script_cve_id("CVE-2015-8151", "CVE-2015-8150", "CVE-2015-8149", "CVE-2015-8148");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:M/C:C/I:C/A:C");
  script_version("2025-02-19T05:37:55+0000");

  script_name("Symantec Encryption Management Server Server Multiple Security Issues");

  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2016&suid=20160218_00");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83268");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83269");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83270");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83271");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Symantec Encryption Management Server's web administration interface was
  susceptible to command execution on the underlying operating system when an authorized but less-privileged administrator
  has console access. Input fields available through the server console did not properly filter arbitrary user input which
  could allow OS command execution with elevated privileges.

  The LDAP service provided by Symantec Encryption Management Server was susceptible to heap memory corruption. Specially-crafted request
  packets could result in corrupted memory block headers leading to a SIGSEGV fault and service halt.");

  script_tag(name:"impact", value:"By leveraging the successful exploitation to the command execution, an unauthorized user could have scheduled
  arbitrary commands to run through existing batch files on the underlying operating system that normally run with root privileges. This could have
  resulted in additional privileged access to the server.

  By successfully manipulating an LDAP request, it could be possible for a user to access the LDAP server to gather information on valid
  administrator accounts on the server. This information could potentially be used for further attempts to gain unauthorized access to the
  server or network.");

  script_tag(name:"solution", value:"Update to version 3.3.2 MP12 or later.");

  script_tag(name:"summary", value:"The management console for Symantec Encryption Management Server (SEMS) is susceptible to potential OS command execution,
  local access elevation of privilege, a heap-based memory corruption resulting in a service crash and potential information disclosure of management console
  logon/account information.");
  script_tag(name:"affected", value:"Symantec Encryption Management Server 3.3.2 before MP12");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-06 03:03:00 +0000 (Tue, 06 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-02-22 13:40:03 +0100 (Mon, 22 Feb 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_symantec_encryption_server_version.nasl");
  script_mandatory_keys("symantec_encryption_server/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version_is_less( version:version, test_version:"3.3.2" ) ) VULN = TRUE;

mp = get_kb_item( "symantec_encryption_server/MP_VALUE" );
build = get_kb_item( "symantec_encryption_server/build" );

if( version == '3.3.2' )
{
  if( mp && int( mp ) < 12 ) VULN = TRUE;
  if( build && int( build ) < 21436 ) VULN = TRUE;
}

if( VULN )
{
  report = 'Installed version: ' + version + '\n';
  if( mp ) report += 'MP:                '  + mp + '\n';
  if( build ) report += 'Installed build:   '  + build + '\n';

  report += '\nFixed version:     3.3.2 MP12\n' +
            'Fixed build:       21436';

  security_message( port:0, data:report );
  exit( 0 );
}
