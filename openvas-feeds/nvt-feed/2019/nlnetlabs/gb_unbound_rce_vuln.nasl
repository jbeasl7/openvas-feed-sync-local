# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nlnetlabs:unbound";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143176");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2019-11-26 04:07:53 +0000 (Tue, 26 Nov 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-30 00:15:00 +0000 (Tue, 30 Jun 2020)");

  script_cve_id("CVE-2019-18934");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unbound DNS Resolver 1.6.4 - 1.9.4 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("unbound_version.nasl");
  script_mandatory_keys("unbound/installed");

  script_tag(name:"summary", value:"Unbound DNS Resolver is prone to a remote code execution (RCE)
  vulnerability under certain conditions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unbound contains a vulnerability that can cause shell code execution after
  receiving a specially crafted answer. This issue can only be triggered if unbound was compiled with
  '--enable-ipsecmod' support, and ipsecmod is enabled and used in the configuration.");

  script_tag(name:"affected", value:"Unbound DNS Resolver versions 1.6.4 - 1.9.4.");

  script_tag(name:"solution", value:"Update to version 1.9.5 or later or apply the provided patch.");

  script_xref(name:"URL", value:"https://www.nlnetlabs.nl/downloads/unbound/CVE-2019-18934.txt");

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

if (version_in_range(version: version, test_version: "1.6.4", test_version2: "1.9.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.9.5");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
