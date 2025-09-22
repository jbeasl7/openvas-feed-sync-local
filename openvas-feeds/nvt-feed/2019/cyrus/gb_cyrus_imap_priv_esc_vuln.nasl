# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cyrus:imap";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112666");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-11-18 13:37:00 +0000 (Mon, 18 Nov 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-18928");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cyrus IMAP 2.5.x < 2.5.14, 3.0.x < 3.0.12 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("secpod_cyrus_imap_server_detect.nasl");
  script_mandatory_keys("cyrus/imap_server/detected");

  script_tag(name:"summary", value:"Cyrus IMAP is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists because an HTTP request may be
  interpreted in the authentication context of an unrelated previous request that arrived over the same connection.");

  script_tag(name:"affected", value:"Cyrus IMAP versions 2.5.0 to 2.5.13 and 3.0.0 to 3.0.11.");

  script_tag(name:"solution", value:"Update to version 2.5.14, 3.0.12 or later.");

  script_xref(name:"URL", value:"https://www.cyrusimap.org/imap/download/release-notes/2.5/x/2.5.14.html");
  script_xref(name:"URL", value:"https://www.cyrusimap.org/imap/download/release-notes/3.0/x/3.0.12.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version: version, test_version: "2.5", test_version2: "2.5.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.14", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "3.0", test_version2: "3.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.12", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
