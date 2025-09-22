# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154835");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-06-26 03:39:38 +0000 (Thu, 26 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-25 15:13:54 +0000 (Mon, 25 Aug 2025)");

  script_cve_id("CVE-2025-49845", "CVE-2025-53102", "CVE-2025-54411");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 3.5.x < 3.5.0.beta8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-49845: The visibility of posts typed whisper is controlled via the
  whispers_allowed_groups site setting. Only users that belong to groups specified in the site
  setting are allowed to view posts typed whisper. However, it has been discovered that users can
  continue to see their own whispers even after losing visibility of posts typed whisper.

  - CVE-2025-53102: When a physical security key is used for 2FA, the server generates a WebAuthn
  challenge, which the client signs. The challenge is not cleared from the user's session after
  authentication, potentially allowing reuse and increasing security risk.

  - CVE-2025-54411: Welcome banner user name string for logged in users can be vulnerable to XSS
  attacks, which affect the user themselves or an admin impersonating them.");

  script_tag(name:"affected", value:"Discourse versions 3.5.x prior to 3.5.0.beta8.");

  script_tag(name:"solution", value:"Update to version 3.5.0.beta8 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-79qw-r73r-69gf");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-hv49-93h5-4wcv");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-5mm6-j5vq-6884");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.5.0.beta", test_version_up: "3.5.0.beta8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.0.beta8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
