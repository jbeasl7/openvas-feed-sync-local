# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146524");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-08-19 09:29:09 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-30 18:01:00 +0000 (Mon, 30 Aug 2021)");

  script_cve_id("CVE-2021-37633", "CVE-2021-37693", "CVE-2021-37703");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 2.8.0.beta5 Security Update");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-37633: Rendering of d-popover tooltips can be susceptible to XSS attacks. This
  vulnerability only affects sites which have modified or disabled Discourse's default Content
  Security Policy.

  - CVE-2021-37693: When adding additional email addresses to an existing account on a Discourse
  site an email token is generated as part of the email verification process. Deleting the
  additional email address does not invalidate an unused token which can then be used in other
  contexts, including resetting a password.

  - CVE-2021-37703: A user's read state for a topic such as the last read post number and the
  notification level is exposed.");

  script_tag(name:"affected", value:"Discourse version 2.8.0.beta1 through 2.8.0.beta4.");

  script_tag(name:"solution", value:"Update to version 2.8.0.beta5 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://meta.discourse.org/t/2-8-0-beta5-pm-improvements-unseen-view-allow-uploaded-avatar-by-trust-level-and-more/202357");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-v3v8-3m5w-pjp9");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-9377-96f4-cww4");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-gq2h-qhg2-phf9");

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

if (version_in_range(version: version, test_version: "2.8.0.beta1", test_version2: "2.8.0.beta4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.0.beta5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
