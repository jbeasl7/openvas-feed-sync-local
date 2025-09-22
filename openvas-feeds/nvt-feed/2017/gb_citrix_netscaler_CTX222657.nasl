# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:netscaler";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106808");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-05-17 13:56:33 +0700 (Wed, 17 May 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)");

  script_cve_id("CVE-2017-7219");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix NetScaler Gateway Heap Overflow Vulnerability (CTX222657)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_citrix_netscaler_consolidation.nasl");
  script_mandatory_keys("citrix/netscaler/detected");

  script_tag(name:"summary", value:"Citrix NetScaler Gateway is prone to a heap overflow
  vulnerability which allows remote authenticated attackers to run arbitrary commands.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A heap overflow vulnerability has been identified in Citrix
  NetScaler Gateway that could allow a remote, authenticated user to execute arbitrary commands on
  the NetScaler Gateway appliance as a root user.");

  script_tag(name:"affected", value:"Citrix NetScaler Gateway 10.1, 10.5, 11.0 and 11.1.");

  script_tag(name:"solution", value:"Update to version 10.1 Build 135.8/135.12, 10.5 Build 65.11,
  11.0 Build 70.12, 11.1 Build 52.13 or later.");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX222657");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!vers = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (get_kb_item("citrix/netscaler/enhanced_build"))
  exit(99);

if (version_in_range(version: vers, test_version: "10.1", test_version2: "10.1.135.7")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "10.1 Build 135.8/135.12");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: vers, test_version: "10.5", test_version2: "10.5.65.10")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "10.5 Build 65.11");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: vers, test_version: "11.0", test_version2: "11.0.70.11")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "11.0 Build 70.12");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: vers, test_version: "11.1", test_version2: "11.1.52.12")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "11.1 Build 52.13");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
