# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trend_micro:deep_discovery_inspector";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106143");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-07-15 16:17:52 +0700 (Fri, 15 Jul 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:29:00 +0000 (Mon, 28 Nov 2016)");

  script_cve_id("CVE-2016-5840");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Trend Micro Deep Discovery Inspector RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_trendmicro_deep_discovery_inspector_detect.nasl");
  script_mandatory_keys("deep_discovery_inspector/detected");

  script_tag(name:"summary", value:"Trend Micro Deep Discovery Inspector is prone to a remote
  command execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"hotfix_upload.cgi allows remote administrators to execute arbitrary code
  via a crafted string.");

  script_tag(name:"impact", value:"A remote authenticated attacker could potentially attain code execution
  under the context of the root user.");

  script_tag(name:"affected", value:"Version 3.7, 3.8 SP1 (3.81), and 3.8 SP2 (3.82).");

  script_tag(name:"solution", value:"Install the vendor patch.");

  script_xref(name:"URL", value:"https://esupport.trendmicro.com/solution/en-US/1114281.aspx");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "3.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7 CP 1263");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.8", test_version2: "3.8.SP2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8 SP2 (3.82) CP 1203");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
