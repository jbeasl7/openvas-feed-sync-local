# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:tp-link:archer_ax21_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171360");
  script_version("2025-04-08T05:43:28+0000");
  script_tag(name:"last_modification", value:"2025-04-08 05:43:28 +0000 (Tue, 08 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-03-28 14:28:54 +0000 (Fri, 28 Mar 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-21 19:31:47 +0000 (Tue, 21 Mar 2023)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-1389", "CVE-2023-27359");

  script_name("TP-Link AX21 Router Devices Multiple Vulnerabilities (Apr 2023)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tp_link_routers_http_detect.nasl");
  script_mandatory_keys("tp-link/router/detected");

  script_tag(name:"summary", value:"TP-Link AX21 router devices are prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-1389: The country parameter, of the write callback for the country form at the
  /cgi-bin/luci/,stok=/locale endpoint is vulnerable to a simple command injection vulnerability.
  The country parameter was used in a call to popen(), which executes as root, but only after first
  being set in an initial request.

  - CVE-2023-27359: The specific flaw exists within the hotplugd daemon. The issue results from
  firewall rule handling that allows an attacker access to resources that should be available to
  the LAN interface only.

  The Mirai BotNet leverages these vulnerabilities to compromise the devices.");

  script_tag(name:"impact", value:"An attacker can leverage these vulnerabilities to execute
  arbitrary code in the context of the root user.");

  script_tag(name:"affected", value:"TP-Link AX21 devices, depending on the hardware version:

  - TP-Link AX21 hardware version 1.20 / 1.26 prior to firmware version 1.3.7 build 20230426

  - TP-Link AX21 hardware version 2.0 / 2.6 prior to firmware version 2.1.8 build 20230426

  - TP-Link AX21 hardware version 3.0 / 3.6 prior to firmware version 1.1.4 build 20230219

  TP-Link AX21 hardware versions 4.6 and 5.6 are not affected.");

  script_tag(name:"solution", value:"Update hardware version 1.20 / 1.26 to firmware version
  1.3.7 build 20230426 or later, hardware version 2.0 / 2.6 to firmware version 2.1.8 build
  20230426 or later and hardware version 3.0 / 3.6 to firmware version 1.1.4 build 20230219 or
  later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2023-11");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/blog/2023/4/21/tp-link-wan-side-vulnerability-cve-2023-1389-added-to-the-mirai-botnet-arsenal");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-451/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-452/");
  script_xref(name:"URL", value:"https://www.tp-link.com/us/support/faq/3643/");
  script_xref(name:"URL", value:"https://www.tp-link.com/us/support/download/archer-ax21/v3/#Firmware");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (!hw_version = get_kb_item("tp-link/router/hw_version"))
  exit(0);

build = get_kb_item("tp-link/router/build");

# nb: Both 1.2 and 1.26 hardware versions have the same firmware
if (hw_version =~ "^1\.2") {
  if (version_is_less(version: version, test_version: "1.3.7")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "1.3.7", fixed_build: "20230426");
    security_message(port: 0, data: report);
    exit(0);
  }
  if (version_is_equal(version: version, test_version: "1.3.7") &&
     (!build || version_is_less(version: build, test_version: "20230426"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "1.3.7", fixed_build: "20230426");
    security_message(port: 0, data: report);
    exit(0);
  }
}

# nb: Both 2.0 and 2.6 hardware versions have the same firmware
if (hw_version =~ "^2\.") {
  if (version_is_less(version: version, test_version: "2.1.8")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "2.1.8", fixed_build: "20230426");
    security_message(port: 0, data: report);
    exit(0);
  }
  if (version_is_equal(version: version, test_version: "2.1.8") &&
     (!build || version_is_less(version: build, test_version: "20230426"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "2.1.8", fixed_build: "20230426");
    security_message(port: 0, data: report);
    exit(0);
  }
}
# nb: Both 3.0 and 3.6 hardware versions have the same firmware
if (hw_version =~ "^3\.") {
  if (version_is_less(version: version, test_version: "1.1.4")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "1.1.4", fixed_build: "20230219");
    security_message(port: 0, data: report);
    exit(0);
  }
  if (version_is_equal(version: version, test_version: "1.1.4") &&
     (!build || version_is_less(version: build, test_version: "20230219"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "1.1.4", fixed_build: "20230219");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
