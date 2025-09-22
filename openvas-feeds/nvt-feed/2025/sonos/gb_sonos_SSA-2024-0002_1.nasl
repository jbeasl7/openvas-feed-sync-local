# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sonos:s2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154374");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-25 03:56:03 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-1050");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sonos Speakers S2 App < 16.6 RCE Vulnerability (SSA-2024-0002)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_sonos_upnp_tcp_detect.nasl");
  script_mandatory_keys("sonos/detected");

  script_tag(name:"summary", value:"Sonos speakers are prone to a remote code execution (RCE)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability exists in the SMB2 protocol implementation
  within the affected product that stems from a Use-After-Free (UAF) condition, which occurs when a
  memory location is accessed after it has been freed, leading to unpredictable behavior.");

  script_tag(name:"impact", value:"A malicious actor could send a specially crafted SMB2 message to
  the affected device, triggering the UAF condition and potentially leading to remote code
  execution.");

  script_tag(name:"affected", value:"Sonos speakers with S2 app prior to version 16.6
  (build 83.1-61240).");

  script_tag(name:"solution", value:"Update to version 16.6 (build 83.1-61240) or later.");

  script_xref(name:"URL", value:"https://www.sonos.com/en-us/security-advisory-2024-0002");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-25-225/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "16.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
