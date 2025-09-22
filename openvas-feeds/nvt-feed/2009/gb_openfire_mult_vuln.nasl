# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:igniterealtime:openfire";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800354");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2009-0496", "CVE-2009-0497");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenFire < 3.6.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openfire_http_detect.nasl");
  script_mandatory_keys("openfire/detected");

  script_tag(name:"summary", value:"OpenFire is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Application fails to sanitise the user inputs in:

  - log parameter to logviewer.jsp and log.jsp files

  - search parameter to group-summary.jsp file

  - username parameter to user-properties.jsp file

  - logDir, maxTotalSize, maxFileSize, maxDays, and logTimeout parameters to audit-policy.jsp file

  - propName parameter to server-properties.jsp file

  - roomconfig_roomname and roomconfig_roomdesc parameters to muc-room-edit-form.jsp file");

  script_tag(name:"impact", value:"Attacker may leverage this issue by executing arbitrary script
  code or injecting HTML or JavaScript code in the context of the affected system and can cause
  directory traversal or XSS attack.");

  script_tag(name:"affected", value:"Openfire prior to version 3.6.3.");

  script_tag(name:"solution", value:"Update to version 3.6.3 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33452");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32935");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32937");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32938");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32939");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32940");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32943");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32944");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32945");
  script_xref(name:"URL", value:"http://svn.igniterealtime.org/svn/repos/openfire/trunk/src/web/log.jsp");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/499880/100/0/threaded");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"3.6.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.6.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
