# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:thekelleys:dnsmasq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151740");
  script_version("2025-03-24T05:38:38+0000");
  script_tag(name:"last_modification", value:"2025-03-24 05:38:38 +0000 (Mon, 24 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-02-15 04:45:14 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-20 16:55:30 +0000 (Tue, 20 Feb 2024)");

  script_cve_id("CVE-2023-49441", "CVE-2023-50387", "CVE-2023-50868");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dnsmasq < 2.90 Multiple Vulnerabilities (KeyTrap)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dnsmasq_consolidation.nasl");
  script_mandatory_keys("thekelleys/dnsmasq/detected");

  script_tag(name:"summary", value:"Dnsmasq is prone to multiple vulenrabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-50387, CVE-2023-50868: Certain DNSSEC aspects of the DNS protocol (in RFC 4035 and
  related RFCs) allow remote attackers to cause a denial of service (CPU consumption) via one or
  more DNSSEC responses when there is a zone with many DNSKEY and RRSIG records, aka the 'KeyTrap'
  issue. The protocol specification implies that an algorithm must evaluate all combinations of
  DNSKEY and RRSIG records.

  - CVE-2023-49441: An integer vverflow via forward_query");

  script_tag(name:"affected", value:"Dnsmasq version 2.89 and prior.");

  script_tag(name:"solution", value:"Update to version 2.90 or later.");

  script_xref(name:"URL", value:"https://thekelleys.org.uk/dnsmasq/CHANGELOG");
  script_xref(name:"URL", value:"https://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=log;h=refs/tags/v2.90");
  script_xref(name:"URL", value:"https://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2023q4/017332.html");
  script_xref(name:"URL", value:"https://thekelleys.org.uk/gitweb/?p=dnsmasq.git;a=commit;h=65c2d6afd67a032f45f40d7e4d620f5d73e5f07d");
  script_xref(name:"URL", value:"https://www.athene-center.de/en/keytrap");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.90")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.90", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
