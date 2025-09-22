# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147355");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2021-12-20 03:23:18 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-13 17:36:00 +0000 (Thu, 13 Jan 2022)");

  script_cve_id("CVE-2021-44854", "CVE-2021-44855", "CVE-2021-44856", "CVE-2021-44857",
                "CVE-2021-44858", "CVE-2021-45038", "CVE-2021-46146", "CVE-2021-46147",
                "CVE-2021-46148", "CVE-2021-46149", "CVE-2021-46150");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.35.5, 1.36.x < 1.36.3, 1.37.x < 1.37.1 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-44854: The REST API publicly caches results from private wikis

  - CVE-2021-44855: There is blind stored XSS via a URL to the Upload Image feature

  - CVE-2021-44856: A title blocked by AbuseFilter can be created via Special:ChangeContentModel
  due to the mishandling of the EditFilterMergedContent hook return value

  - CVE-2021-44857: It is possible to replace the content of any arbitrary page (that the user
  doesn't have edit rights for)

  - CVE-2021-44858: The 'undo' feature allows an attacker to view the contents of arbitrary
  revisions, regardless of whether they had permissions to do so

  - CVE-2021-45038: The 'rollback' feature could be passed a specially crafted parameter that
  allows an attacker to view the contents of arbitrary pages, regardless of whether they had
  permissions to do so

  - CVE-2021-46146: The WikibaseMediaInfo component is vulnerable to XSS via the caption fields for
  a given media file

  - CVE-2021-46147: MassEditRegex allows CSRF

  - CVE-2021-46148: Some unprivileged users can view confidential information (e.g., IP addresses
  and User-Agent headers for election traffic) on a testwiki SecurePoll instance

  - CVE-2021-46149: A denial of service (resource consumption) can be accomplished by searching for
  a very long key in a Language Name Search

  - CVE-2021-46150: Special:CheckUserLog allows CheckUser XSS because of date mishandling, as
  demonstrated by an XSS payload in MediaWiki:October");

  script_tag(name:"affected", value:"MediaWiki prior to version 1.35.5, version 1.36.x through
  1.36.2 and 1.37.0.");

  script_tag(name:"solution", value:"Update to version 1.35.5, 1.36.3, 1.37.1 or later.");

  script_xref(name:"URL", value:"https://www.mediawiki.org/wiki/2021-12_security_release/FAQ");

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

if (version_is_less(version: version, test_version: "1.35.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.35.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.36.0", test_version2: "1.36.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.36.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "1.37.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.37.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
