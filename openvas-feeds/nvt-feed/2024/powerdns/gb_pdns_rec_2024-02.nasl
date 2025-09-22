# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:recursor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152142");
  script_version("2024-05-03T15:38:41+0000");
  script_tag(name:"last_modification", value:"2024-05-03 15:38:41 +0000 (Fri, 03 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-03 05:37:10 +0000 (Fri, 03 May 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2024-25583");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Recursor DoS Vulnerability (2024-02)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor/installed");

  script_tag(name:"summary", value:"PowerDNS Recursor is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A crafted response from an upstream server the recursor has
  been configured to forward-recurse to can cause a Denial of Service in the Recursor. The default
  configuration of the Recursor does not use recursive forwarding and is not affected.");

  script_tag(name:"affected", value:"PowerDNS Recursor version 4.8.7 and prior, 4.9.x through 4.9.4
  and 5.0.x through 5.0.3.");

  script_tag(name:"solution", value:"Update to version 4.8.8, 4.9.5, 5.0.4 or later.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/security-advisories/powerdns-advisory-2024-02.html");

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

if (version_is_less(version: version, test_version: "4.8.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.8");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.9.0", test_version_up: "4.9.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.5");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "5.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.4");
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
