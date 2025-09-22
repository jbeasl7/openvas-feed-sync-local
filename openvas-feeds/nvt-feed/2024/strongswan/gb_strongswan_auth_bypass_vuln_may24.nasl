# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:strongswan:strongswan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126782");
  script_version("2024-05-16T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-15 10:48:43 +0000 (Wed, 15 May 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-4967");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("strongSwan 5.9.2 < 5.9.6 Authorization Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_strongswan_ssh_login_detect.nasl");
  script_mandatory_keys("strongswan/detected");

  script_tag(name:"summary", value:"strongSwan is prone to an authorization bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An old bug in our TLS library that caused IKE/EAP identities to
  not get matched against certificates in TLS-based EAP methods can possibly lead to an
  authorization bypass vulnerability.");

  script_tag(name:"affected", value:"strongSwan version 5.9.2 prior to 5.9.6.");

  script_tag(name:"solution", value:"Update to version 5.9.6 or later.");

  script_xref(name:"URL", value:"https://www.strongswan.org/blog/2024/05/13/strongswan-vulnerability-(cve-2022-4967).html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "5.9.2", test_version_up: "5.9.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.6", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
