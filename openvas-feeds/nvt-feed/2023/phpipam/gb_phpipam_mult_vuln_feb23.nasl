# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpipam:phpipam";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126331");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-02-06 08:07:10 +0000 (Mon, 06 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-12 04:46:00 +0000 (Sun, 12 Feb 2023)");

  script_cve_id("CVE-2023-0676", "CVE-2023-0677", "CVE-2023-0678");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpIPAM < 1.5.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpipam_http_detect.nasl");
  script_mandatory_keys("phpipam/detected");

  script_tag(name:"summary", value:"phpIPAM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-0676: Reflected XSS arises when an application receives data in an HTTP request and
  includes that data within the immediate response in an unsafe way.

  - CVE-2023-0677: Reflected XSS arises when an application receives data in an HTTP request and
  includes that data within the immediate response in an unsafe way.

  - CVE-2023-0678: An unauthenticated user could download the list of high-usage IP subnets that
  contains sensitive information such as a subnet description, IP ranges, and usage rates via
  find_full_subnets.php endpoint."); #Note: The description for both CVE is the same.

  script_tag(name:"affected", value:"phpIPAM prior to version 1.5.1.");

  script_tag(name:"solution", value:"Update to version 1.5.1 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/b72d4f0c-8a96-4b40-a031-7d469c6ab93b/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/d280ae81-a1c9-4a50-9aa4-f98f1f9fd2c0/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/8d299377-be00-46dc-bebe-3d439127982f/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
