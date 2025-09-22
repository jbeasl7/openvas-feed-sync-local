# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bmc:track-it%21";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106147");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-19 11:00:37 +0700 (Tue, 19 Jul 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-26 19:39:00 +0000 (Mon, 26 Feb 2018)");

  # nb: The two 2015 CVEs had been included in this VT since the beginning but haven't been assigned
  # so far. They are kept for now for "historical" reasons.
  script_cve_id("CVE-2015-8273", "CVE-2015-8274", "CVE-2016-6598", "CVE-2016-6599");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("BMC Track-It! < 11.4 Hotfix 3 (11.4.0.440) Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_bmc_trackit_http_detect.nasl");
  script_mandatory_keys("bmc/trackit/detected");

  script_tag(name:"summary", value:"BMC Track-It! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2016-6598: Remote code execution via file upload

  - CVE-2016-6599: Domain administrator and SQL server user credentials disclosure");

  script_tag(name:"impact", value:"An unauthenticated attacker may upload arbitrary files and
  execute any action.");

  script_tag(name:"affected", value:"BMC Track-It! prior to version 11.4 Hotfix 3 (11.4.0.440).");

  script_tag(name:"solution", value:"Update to version 11.4 Hotfix 3 (11.4.0.440) or later.");

  script_xref(name:"URL", value:"https://communities.bmc.com/community/bmcdn/bmc_track-it/blog/2016/01/04/track-it-security-advisory-24-dec-2015");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/2713");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2018/Jan/92");
  script_xref(name:"URL", value:"https://github.com/pedrib/PoC/blob/master/advisories/bmc-track-it-11.4.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "11.4.0.440")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.4.0.440");
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
