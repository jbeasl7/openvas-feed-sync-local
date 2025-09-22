# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117008");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-11-05 13:06:40 +0000 (Thu, 05 Nov 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-31 01:39:00 +0000 (Thu, 31 Oct 2019)");

  script_cve_id("CVE-2012-0046");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki Information Disclosure Vulnerability (Jan 2012) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"prop=revisions allows deleted text to be exposed through
  cache pollution.");

  script_tag(name:"affected", value:"MediaWiki versions before 1.17.2 and 1.18.x before 1.18.1.");

  script_tag(name:"solution", value:"Update to version 1.17.2, 1.18.1 or later.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2012-0046");
  script_xref(name:"URL", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=33117");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2012/01/12/6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.17.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.17.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

else if (version =~ "^1\.18" && version_is_less(version: version, test_version: "1.18.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.18.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
