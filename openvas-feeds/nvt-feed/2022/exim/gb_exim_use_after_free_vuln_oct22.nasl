# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exim:exim";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126183");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2022-10-21 10:31:17 +0000 (Fri, 21 Oct 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-24 15:50:00 +0000 (Mon, 24 Oct 2022)");

  script_cve_id("CVE-2022-3620");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Exim 4.95 - 4.96 Use-After-Free Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_exim_smtp_detect.nasl");
  script_mandatory_keys("exim/detected");

  script_tag(name:"summary", value:"Exim is prone to a use-after-free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Exim has an use-after-free in dmarc_dns_lookup where the result
  of dns_lookup in dnsa is freed before the required data is copied out.");

  script_tag(name:"affected", value:"Exim version 4.95 through 4.96.

  Note: The issue has been introduced with commit 92583637b25b6bde926f9ca6be7b085e5ac8b1e6
  included in the final release 4.95 and has been fixed with the commit
  12fb3842f81bcbd4a4519d5728f2d7e0e3ca1445 included in the next upcoming version 4.97.");

  # nb: Fixed version wasn't released yet, but the flaw is already fixed and will be released in upcoming patch.
  script_tag(name:"solution", value:"Update to version 4.97 or later.");

  script_xref(name:"URL", value:"https://github.com/Exim/exim/commit/12fb3842f81bcbd4a4519d5728f2d7e0e3ca1445");
  script_xref(name:"URL", value:"https://github.com/Exim/exim/commit/92583637b25b6bde926f9ca6be7b085e5ac8b1e6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_in_range(version: version, test_version: "4.95", test_version2: "4.96")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.97");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
