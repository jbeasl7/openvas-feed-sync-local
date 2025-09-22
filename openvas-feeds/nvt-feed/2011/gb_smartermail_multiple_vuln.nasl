# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:smartertools:smartermail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901196");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("SmarterMail Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41677/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41485/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16955/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/99169/smartermail-xsstraversalshell.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_smartermail_detect.nasl");
  script_mandatory_keys("SmarterMail/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to conduct cross site scripting,
  shell upload and directory traversal attacks.");
  script_tag(name:"affected", value:"SmarterTools SmarterMail versions 7.4 and prior.");
  script_tag(name:"insight", value:"Input passed in the 'path' parameter to Main/frmStoredFiles.aspx, the 'edit'
  parameter to UserControls/Popups/frmAddFileStorageFolder.aspx, the
  'SubjectBox_SettingText' parameter to Main/Calendar/frmEvent.aspx, the 'url'
  parameter to UserControls/Popups/frmHelp.aspx, the 'folder' parameter to
  UserControls/Popups/frmDeleteConfirm.aspx, the 'editfolder' parameter to
  UserControls/Popups/frmEventGroup.aspx, the 'deletefolder' parameter to
  UserControls/Popups/frmEventGroup.aspx, and the 'bygroup' parameter to
  Main/Alerts/frmAlerts.aspx is not properly sanitised before being returned
  to the user.");
  script_tag(name:"solution", value:"Upgrade to SmarterTools SmarterMail 8.0 or later.");
  script_tag(name:"summary", value:"SmarterMail is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.smartertools.com/smartermail/mail-server-software.aspx");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"7.0", test_version2:"7.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
