# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nlnetlabs:unbound";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148791");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2022-09-30 03:10:28 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-28 19:32:00 +0000 (Wed, 28 Sep 2022)");

  script_cve_id("CVE-2022-3204");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unbound DNS Resolver < 1.16.3 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("unbound_version.nasl");
  script_mandatory_keys("unbound/installed");

  script_tag(name:"summary", value:"Unbound DNS Resolver is prone to a denial of service (DoS)
  vulnerability 'Non-Responsive Delegation Attack' (NRDelegation Attack).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The NRDelegation Attack can exploit resolvers by having a
  malicious delegation with a considerable number of non responsive nameservers. It can trigger
  high CPU usage in some resolver implementations that continually look in the cache for resolved
  NS records in that delegation. This can lead to degraded performance and eventually denial of
  service in orchestrated attacks.");

  script_tag(name:"affected", value:"Unbound DNS Resolver version 1.16.2 and prior.");

  script_tag(name:"solution", value:"Update to version 1.16.3 or later.");

  script_xref(name:"URL", value:"https://www.nlnetlabs.nl/downloads/unbound/CVE-2022-3204.txt");

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

if (version_is_less(version: version, test_version: "1.16.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.16.3");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
