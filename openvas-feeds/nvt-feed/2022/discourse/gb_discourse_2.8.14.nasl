# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148986");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-12-05 02:52:00 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-13 15:55:00 +0000 (Fri, 13 Jan 2023)");

  script_cve_id("CVE-2023-22453", "CVE-2023-22454", "CVE-2022-23548", "CVE-2022-23549",
                "CVE-2022-46159", "CVE-2022-46168", "CVE-2022-46177", "CVE-2023-22455");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 2.8.14 Multiple Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-22453: Exposure of user post counts per topic to unauthorized users

  - CVE-2023-22454: XSS through pending post titles descriptions

  - CVE-2023-22455: XSS through tag descriptions

  - CVE-2022-23548: Regex susceptible to ReDOS

  - CVE-2022-23549: Bypass of post max_length using HTML comments

  - CVE-2022-46159: Any authenticated user can create an unlisted topic

  - CVE-2022-46168: Group SMTP user emails are exposed in CC email header

  - CVE-2022-46177: Password reset link can lead to in account takeover if user changes to a new
  email");

  script_tag(name:"affected", value:"Discourse prior to version 2.8.14.");

  script_tag(name:"solution", value:"Update to version 2.8.14 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-xx97-6494-p2rv");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-ggq4-4qxc-c462");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-7rw2-f4x7-7pxf");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-p47g-v5wr-p4xp");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-qf99-xpx6-hgxp");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-8p7g-3wm6-p3rm");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-5www-jxvf-vrc3");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-5rq6-466r-6mr9");

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

if (version_is_less(version: version, test_version: "2.8.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
