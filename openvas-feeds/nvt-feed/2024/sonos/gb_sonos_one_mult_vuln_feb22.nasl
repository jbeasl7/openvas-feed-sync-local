# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/a:sonos:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170809");
  script_version("2024-09-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-09-19 05:05:57 +0000 (Thu, 19 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-16 11:03:02 +0000 (Mon, 16 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-07 14:38:21 +0000 (Mon, 07 Mar 2022)");

  script_cve_id("CVE-2022-24046", "CVE-2022-24049");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: Build not detected

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sonos One Speakers S1 App < 11.2.3 build 57923290, S2 App < 13.4.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_sonos_upnp_tcp_detect.nasl");
  script_mandatory_keys("sonos/detected");

  script_tag(name:"summary", value:"Sonos One speakers are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2022-24046: Integer underflow remote code execution (RCE)

  - CVE-2022-24049: ALAC frame parser stack-based buffer overflow");

  script_tag(name:"affected", value:"- Sonos One speakers with S1 app prior to version 11.2.3 build
  57923290

  - Sonos One speakers with S2 app prior to version 13.4.1");

  script_tag(name:"solution", value:"- Update Sonos One speakers with S1 app to version 11.2.13
  build 57923290 or later

  - Update Sonos One speakers with S2 app to version 13.4.1 or later");

  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-22-260/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-22-261/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

if (!model = get_kb_item("sonos/model"))
  exit(0);

if (model !~ "^One$")
  exit(99);

cpe = infos["cpe"];
port = infos["port"];

if (!version = get_app_version(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

if (cpe == "cpe:/a:sonos:s1") {
  if (version_is_less(version: version, test_version: "11.2.13")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "11.2.13 build 57923290");
    security_message(port: port, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/a:sonos:s2") {
  if (version_is_less(version: version, test_version: "13.4.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.4.1");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
