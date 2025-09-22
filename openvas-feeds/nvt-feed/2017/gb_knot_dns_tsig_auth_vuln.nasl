# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:knot:dns";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106938");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-07-11 11:31:58 +0700 (Tue, 11 Jul 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-20 15:23:00 +0000 (Fri, 20 Jan 2023)");

  script_cve_id("CVE-2017-11104");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("KNOT DNS Server Security Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_knot_dns_version_detect.nasl");
  script_mandatory_keys("KnotDNS/installed");

  script_tag(name:"summary", value:"A flaw was found in the way KNOT handled TSIG authentication for dynamic
updates. A remote attacker able to communicate with an authoritative KNOT server could use this flaw to
manipulate the contents of a zone, by forging a valid TSIG or SIG(0) signature for a dynamic update request.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"KNOT DNS Server prior to version 2.4.5 and 2.5.2.");

  script_tag(name:"solution", value:"Update to version 2.4.5, 2.5.2 or later.");

  script_xref(name:"URL", value:"https://lists.nic.cz/pipermail/knot-dns-users/2017-June/001144.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "2.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.5");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.5.0", test_version2: "2.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.2");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
