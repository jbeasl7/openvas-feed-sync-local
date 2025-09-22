# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/a:sonos:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154375");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-25 04:08:58 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-1048", "CVE-2025-1049");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sonos Speakers S1 App < 11.15.1, S2 App < 16.6 Multiple RCE Vulnerabilities (SSA-2024-0002)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_sonos_upnp_tcp_detect.nasl");
  script_mandatory_keys("sonos/detected");

  script_tag(name:"summary", value:"Sonos speakers are prone to multiple remote code execution
  (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-1048: Remote code execution (RCE) in the handling of HLS

  - CVE-2025-1049: Remote code execution (RCE) in the MPEG-TS parsing code");

  script_tag(name:"affected", value:"- Sonos speakers with S1 app prior to version 11.15.1
  (build 57.22-61162)

  - Sonos speakers with S2 app prior to version 16.6 (build 83.1-61240)");

  script_tag(name:"solution", value:"- Update Sonos speakers with S1 app to version 11.15.1
  (build 57.22-61162) or later

  - Update Sonos speakers with S2 app to version 16.6 (build 83.1-61240) or later");

  script_xref(name:"URL", value:"https://www.sonos.com/en-us/security-advisory-2024-0002");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-225/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-224/");

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
  if (version_is_less(version: version, test_version: "11.15.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "11.15.1");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/a:sonos:s2") {
  if (version_is_less(version: version, test_version: "16.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "16.6");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
