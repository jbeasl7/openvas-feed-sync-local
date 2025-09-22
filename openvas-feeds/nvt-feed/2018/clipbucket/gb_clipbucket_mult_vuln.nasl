# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clipbucket_project:clipbucket";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140826");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-02-28 12:21:38 +0700 (Wed, 28 Feb 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-27 14:48:00 +0000 (Tue, 27 Mar 2018)");

  script_cve_id("CVE-2018-7666", "CVE-2018-7664", "CVE-2018-7665");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # no release version available

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClipBucket Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_clipbucket_detect.nasl");
  script_mandatory_keys("clipbucket/Installed");

  script_tag(name:"summary", value:"ClipBucket is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"ClipBucket is prone to multiple vulnerabilities:

  - Unauthenticated OS Command Injection

  - Unauthenticated Arbitrary File Upload

  - Unauthenticated Blind SQL Injection");

  script_tag(name:"affected", value:"ClipBucket prior to version 4.0.0 Release 4902.");

  script_tag(name:"solution", value:"Update to version 4.0.0 Release 4902 or later.");

  script_xref(name:"URL", value:"https://www.sec-consult.com/en/blog/advisories/os-command-injection-arbitrary-file-upload-sql-injection-in-clipbucket/index.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.0 Release 4902");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
