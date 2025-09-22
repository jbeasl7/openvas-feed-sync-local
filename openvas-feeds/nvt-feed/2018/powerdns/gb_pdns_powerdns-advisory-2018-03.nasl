# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:authoritative_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141653");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-11-07 09:40:09 +0700 (Wed, 07 Nov 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2018-10851");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Authoritative Server Zone Record DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_tag(name:"summary", value:"An issue has been found in PowerDNS Authoritative Server allowing an
authorized user to cause a memory leak by inserting a specially crafted record in a zone under their control, then
sending a DNS query for that record. The issue is due to the fact that some memory is allocated before the parsing
and is not always properly released if the record is malformed.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Authoritative Server versions 3.3.0 to 4.1.4.");

  script_tag(name:"solution", value:"Upgrade to version 4.0.6, 4.1.5 or later.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/authoritative/security-advisories/powerdns-advisory-2018-03.html");

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

if (version_in_range(version: version, test_version: "3.3.0", test_version2: "4.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.6");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.1", test_version2: "4.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.5");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(0);
