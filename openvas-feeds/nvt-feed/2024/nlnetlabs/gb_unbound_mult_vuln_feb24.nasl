# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nlnetlabs:unbound";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151742");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-02-16 02:26:10 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-20 16:55:30 +0000 (Tue, 20 Feb 2024)");

  script_cve_id("CVE-2023-50387", "CVE-2023-50868");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unbound DNS Resolver < 1.19.1 Multiple DoS Vulnerabilities (KeyTrap)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("unbound_version.nasl");
  script_mandatory_keys("unbound/installed");

  script_tag(name:"summary", value:"Unbound DNS Resolver is prone to multiple denial of service
  (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The KeyTrap vulnerability works by using a combination of Keys
  (also colliding Keys), Signatures and number of RRSETs on a malicious zone. Answers from that
  zone can force a DNSSEC validator down a very CPU intensive and time costly validation path.

  The NSEC3 vulnerability uses specially crafted responses on a malicious zone with multiple NSEC3
  RRSETs to force a DNSSEC validator down a very CPU intensive and time costly NSEC3 hash
  calculation path.

  Both can force Unbound to spend an enormous time (comparative to regular traffic) validating a
  single specially crafted DNSSEC response while everything else is on hold for that thread. A
  trivially orchestrated attack could render all threads busy with such responses leading to denial
  of service.");

  script_tag(name:"affected", value:"Unbound DNS Resolver version 1.19.0 and prior.");

  script_tag(name:"solution", value:"Update to version 1.19.1 or later.");

  script_xref(name:"URL", value:"https://nlnetlabs.nl/news/2024/Feb/13/unbound-1.19.1-released/");
  script_xref(name:"URL", value:"https://nlnetlabs.nl/downloads/unbound/CVE-2023-50387_CVE-2023-50868.txt");
  script_xref(name:"URL", value:"https://www.athene-center.de/en/keytrap");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "1.19.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.19.1");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
