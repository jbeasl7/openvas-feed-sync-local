# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:brocade:network_advisor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106516");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-01-16 10:12:31 +0700 (Mon, 16 Jan 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-10 01:29:00 +0000 (Thu, 10 May 2018)");

  script_cve_id("CVE-2016-8204", "CVE-2016-8205", "CVE-2016-8206", "CVE-2016-8207");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Brocade Network Advisor Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_brocade_network_advisor_detect.nasl");
  script_mandatory_keys("brocade_network_advisor/installed");

  script_tag(name:"summary", value:"Brocade Network Advisor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Brocade Network Advisor is prone to multiple vulnerabilities:

  - Directory Traversal vulnerability in FileReceiveServlet (CVE-2016-8204)

  - Directory Traversal vulnerability in DashboardFileReceiveServlet (CVE-2016-8205)

  - Directory Traversal vulnerability in servlet SoftwareImageUpload (CVE-2016-8206)

  - Directory Traversal vulnerability in CliMonitorReportServlet (CVE-2016-8207)");

  script_tag(name:"impact", value:"A remote attacker may upload and execute malicious files, read or delete
arbitrary files.");

  script_tag(name:"affected", value:"Brocade Network Advisor 14.0.2 and prior.");

  script_tag(name:"solution", value:"Upgrade to Version 14.0.3, 14.1.1 or later");

  script_xref(name:"URL", value:"https://www.brocade.com/content/dam/common/documents/content-types/security-bulletin/brocade-security-advisory-2016-177.htm");
  script_xref(name:"URL", value:"https://www.brocade.com/content/dam/common/documents/content-types/security-bulletin/brocade-security-advisory-2016-178.htm");
  script_xref(name:"URL", value:"https://www.brocade.com/content/dam/common/documents/content-types/security-bulletin/brocade-security-advisory-2016-179.htm");
  script_xref(name:"URL", value:"https://www.brocade.com/content/dam/common/documents/content-types/security-bulletin/brocade-security-advisory-2016-180.htm");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "14.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.0.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
