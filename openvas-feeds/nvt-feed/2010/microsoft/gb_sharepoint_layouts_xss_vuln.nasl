# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb: While only Microsoft SharePoint is mentioned the initial version of this VT had used / probed
# the "MicrosoftSharePointTeamServices" header version and thus this CPE is used here.
CPE = "cpe:/a:microsoft:sharepoint_team_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902176");
  script_version("2025-08-06T05:45:41+0000");
  script_tag(name:"last_modification", value:"2025-08-06 05:45:41 +0000 (Wed, 06 Aug 2025)");
  script_tag(name:"creation_date", value:"2010-05-04 09:40:09 +0200 (Tue, 04 May 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-0817");
  script_name("Microsoft SharePoint '_layouts/help.aspx' XSS Vulnerability (MS10-039)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("microsoft_windows_sharepoint_services_http_detect.nasl");
  script_mandatory_keys("microsoft/windows_sharepoint_team_services/detected");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-039");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/SecurityAdvisories/2010/983438");
  script_xref(name:"URL", value:"https://web.archive.org/web/20111227044841/http://www.securityfocus.com/archive/1/archive/1/509683/100/0/threaded");
  script_xref(name:"URL", value:"https://web.archive.org/web/20120119162638/http://www.htbridge.ch/advisory/xss_in_microsoft_sharepoint_server_2007.html");

  script_tag(name:"summary", value:"Microsoft SharePoint Server is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This flaw is due to insufficient validation of user supplied
  data passed into 'cid0' parameter in the '_layouts/help.aspx' in SharePoint
  Team Services.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users
  to compromise the application, theft of cookie-based authentication credentials,
  disclosure or modification of sensitive data.");

  script_tag(name:"affected", value:"- Microsoft Windows SharePoint Services 30 SP 1

  - Microsoft Office SharePoint Server SP1 2007 version 12.0.0.6421 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  # nb: The version in the "MicrosoftSharePointTeamServices" header might not be fully reliable...
  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"12.0", test_version2:"12.0.0.6421")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"12.0 - 12.0.0.6421");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
