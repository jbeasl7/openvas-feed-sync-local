# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/a:sonos:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131018");
  script_version("2024-09-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-09-19 05:05:57 +0000 (Thu, 19 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-04-09 08:21:13 +0000 (Tue, 09 Apr 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2023-50810", "CVE-2023-50809");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sonos Speakers S1 App < 11.12, S2 App < 15.9 Multiple Code Execution Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_sonos_upnp_tcp_detect.nasl");
  script_mandatory_keys("sonos/detected");

  script_tag(name:"summary", value:"Sonos speakers are prone to multiple code execution
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-50810: Component U-Boot allows to persistent arbitrary code execution with Linux
  kernel privileges.

  - CVE-2023-50809: Wireless driver in affected devices does not properly validate an information
  element while negotiating a WPA2 four-way handshake.");

  script_tag(name:"affected", value:"- Sonos speakers with S1 app prior to version 11.12

  - Sonos speakers with S2 app prior to version 15.9");

  script_tag(name:"solution", value:"- Update Sonos speakers with S1 app to version 11.12 or later

  - Update Sonos speakers with S2 app to version 15.9 or later");

  script_xref(name:"URL", value:"https://www.sonos.com/en-us/security-advisory-2024-0001");
  script_xref(name:"URL", value:"https://www.nccgroup.com/media/ue5cwm0o/bhus24_sonos_briefings_slides.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!version = get_app_version(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/a:sonos:s1") {
  if (version_is_less(version: version, test_version: "11.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "11.12");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/a:sonos:s2") {
  if (version_is_less(version: version, test_version: "15.9")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.9");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
