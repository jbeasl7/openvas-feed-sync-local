# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nlnetlabs:unbound";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114414");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-03-07 14:16:22 +0000 (Thu, 07 Mar 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-17 16:56:50 +0000 (Tue, 17 Dec 2024)");

  script_cve_id("CVE-2024-1931");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unbound DNS Resolver 1.18.0 - 1.19.1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("unbound_version.nasl");
  script_mandatory_keys("unbound/installed");

  script_tag(name:"summary", value:"Unbound DNS Resolver is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Recent versions of Unbound contain a vulnerability that can
  cause denial of service by a certain code path that can lead to an infinite loop.

  This issue can only be triggered if the non-default option 'ede: yes' is used, Unbound would reply
  with attached EDE information on a positive reply, and the client's buffer size is relatively
  smaller than the needed space to include EDE records.");

  script_tag(name:"affected", value:"Unbound DNS Resolver versions 1.18.0 through 1.19.1.");

  script_tag(name:"solution", value:"Update to version 1.19.2 or later.");

  script_xref(name:"URL", value:"https://nlnetlabs.nl/news/2024/Mar/07/unbound-1.19.2-released/");
  script_xref(name:"URL", value:"https://www.nlnetlabs.nl/downloads/unbound/CVE-2024-1931.txt");

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

if (version_in_range(version: version, test_version: "1.18.0", test_version2: "1.19.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.19.2");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
