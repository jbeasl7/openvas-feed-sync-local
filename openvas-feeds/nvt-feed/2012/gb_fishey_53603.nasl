# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlassian:fisheye";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103490");
  script_version("2024-03-04T14:37:58+0000");

  script_name("Atlassian JIRA FishEye and Crucible Plugins XML Parsing Unspecified Security Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53603");
  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/FE-4016");
  script_xref(name:"URL", value:"http://confluence.atlassian.com/display/FISHEYE/FishEye+and+Crucible+Security+Advisory+2012-05-17");

  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-05-18 12:55:55 +0200 (Fri, 18 May 2012)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_FishEye_detect.nasl");
  script_mandatory_keys("FishEye/installed");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"The FishEye and Crucible plugins for JIRA are prone to an
unspecified security vulnerability because they fail to properly
handle crafted XML data.

Exploiting this issue allows remote attackers to cause denial-of-
service conditions or to disclose local sensitive files in the context
of an affected application.

FishEye and Crucible versions up to and including 2.7.11 are
vulnerable.");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:vers, test_version:"2.7", test_version2:"2.7.11") ||
   version_in_range(version:vers, test_version:"2.6", test_version2:"2.6.7")  ||
   version_in_range(version:vers, test_version:"2.5", test_version2:"2.5.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
