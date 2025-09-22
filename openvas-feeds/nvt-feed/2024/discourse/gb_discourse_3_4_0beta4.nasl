# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153673");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2024-12-20 04:25:23 +0000 (Fri, 20 Dec 2024)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-26 02:19:59 +0000 (Tue, 26 Aug 2025)");

  script_cve_id("CVE-2024-49765", "CVE-2024-52794", "CVE-2024-53991", "CVE-2024-56328",
                "CVE-2025-22601", "CVE-2025-22602", "CVE-2024-53266", "CVE-2024-53851",
                "CVE-2024-53994");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 3.4.x < 3.4.0.beta4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-49765: Bypass of Discourse Connect using other login paths if enabled

  - CVE-2024-52794: Magnific lightbox susceptible to XSS

  - CVE-2024-53991: Potential Backup file leaked via Nginx

  - CVE-2024-56328: HTMLi (XSS without CSP) via Onebox urls

  - CVE-2025-22601: Client Side Path Traversal using activate account route

  - CVE-2025-22602: Stored DOM-based XSS (without CSP) via video placeholders

  - CVE-2024-53266: XSS via topic titles when CSP disabled

  - CVE-2024-53851: Partial DoS via inline oneboxes

  - CVE-2024-53994: Potential bypass of chat permissions");

  script_tag(name:"affected", value:"Discourse versions 3.4.x prior to 3.4.0.beta4.");

  script_tag(name:"solution", value:"Update to version 3.4.0.beta4 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-v8rf-pvgm-xxf2");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-m3v4-v2rp-hfm9");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-567m-82f6-56rv");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-j855-mhxj-x6vg");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-gvpp-v7mp-wxxw");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-jcjx-694p-c5m3");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-hw4j-4hg7-22h2");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-49rv-574x-wgpc");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-mrpw-gwj7-98r6");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.4.0.beta", test_version_up: "3.4.0.beta4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.0.beta4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
