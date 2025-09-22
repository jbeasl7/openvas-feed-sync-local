# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlassian:bamboo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106652");
  script_version("2024-07-26T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-07-26 05:05:35 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-03-15 11:39:14 +0700 (Wed, 15 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-25 13:58:42 +0000 (Thu, 25 Jul 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-5638");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian Bamboo Struts2 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_bamboo_detect.nasl");
  script_mandatory_keys("AtlassianBamboo/Installed");

  script_tag(name:"summary", value:"Atlassian Bamboo is prone to a remote code execution (RCE)
  vulnerability in Struts2.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Bamboo uses a version of Struts 2 that is vulnerable to CVE-2017-5638.
Attackers can use this vulnerability to execute Java code of their choice on the system.");

  script_tag(name:"affected", value:"Atlassiona Bamboo 5.1 until 5.14.4, 5.15.0 until 5.15.2.");

  script_tag(name:"solution", value:"Update to 5.14.5, 5.15.3 or later.");

  script_xref(name:"URL", value:"https://jira.atlassian.com/browse/BAM-18242");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "5.1.0", test_version2: "5.14.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.14.5");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.15.0", test_version2: "5.15.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.15.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
