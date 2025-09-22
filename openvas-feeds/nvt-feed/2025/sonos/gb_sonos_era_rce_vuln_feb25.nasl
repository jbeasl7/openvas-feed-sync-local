# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/a:sonos:era";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155030");
  script_version("2025-07-28T05:44:47+0000");
  script_tag(name:"last_modification", value:"2025-07-28 05:44:47 +0000 (Mon, 28 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-25 09:18:16 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-1051");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sonos Era < 83.1-61240 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_sonos_device_airplay_detect.nasl");
  script_mandatory_keys("sonos/device/detected");

  script_tag(name:"summary", value:"Sonos Era speakers are prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists within the processing of ALAC data. The issue
  results from the lack of proper validation of the length of user-supplied data prior to copying
  it to a heap-based buffer. An attacker can leverage this vulnerability to execute code in the
  context of the anacapa user.");

  script_tag(name:"affected", value:"Sonos Era 300 speakers prior to version 83.1-61240. Other
  products may be affected as well.");

  script_tag(name:"solution", value:"Update to version 83.1-61240 or later.");

  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-311/");

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

if (version_is_less(version: version, test_version: "83.1.61240")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "83.1-61240");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
