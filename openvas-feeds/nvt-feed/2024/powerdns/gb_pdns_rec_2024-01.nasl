# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151736");
  script_version("2024-02-21T05:06:27+0000");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:27 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-15 03:38:10 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-20 16:55:30 +0000 (Tue, 20 Feb 2024)");

  script_cve_id("CVE-2023-50387", "CVE-2023-50868");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor Multiple DoS Vulnerabilities (2024-01, KeyTrap)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker can publish a zone that contains crafted DNSSEC
  related records. While validating results from queries to that zone using the RFC mandated
  algorithms, the Recursor's resource usage can become so high that processing of other queries is
  impacted, resulting in a denial of service.");

  script_tag(name:"affected", value:"PowerDNS Recursor version 4.8.5 and prior, 4.9.x through 4.9.2
  and 5.0.x through 5.0.1.");

  script_tag(name:"solution", value:"Update to version 4.8.6, 4.9.3, 5.0.2 or later.");

  script_xref(name:"URL", value:"https://blog.powerdns.com/2024/02/13/powerdns-recursor-4-8-6-4-9-3-5-0-2-released");
  script_xref(name:"URL", value:"https://www.athene-center.de/en/keytrap");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "4.8.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.6");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.9.0", test_version_up: "4.9.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.3");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "5.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.2");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
