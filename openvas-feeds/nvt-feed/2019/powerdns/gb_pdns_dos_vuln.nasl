# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:powerdns:authoritative_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143166");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-11-25 04:08:13 +0000 (Mon, 25 Nov 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-04 18:15:00 +0000 (Fri, 04 Dec 2020)");

  script_cve_id("CVE-2019-10203");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Authoritative Server 4.0 < 4.2.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_tag(name:"summary", value:"PowerDNS Authoritative Server is prone to a denial of service
  (DoS) vulnerability when encountering a serial between 2^31 and 2^32-1 while trying to notify a
  slave.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Authoritative 4.0 prior to 4.2.0.");

  script_tag(name:"solution", value:"Update to version 4.2.0 or later.");

  script_xref(name:"URL", value:"https://github.com/PowerDNS/pdns/issues/6815");

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

if (version =~ "^4\." && version_is_less(version: version, test_version: "4.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.0");
  security_message(data: report, port: port, proto: proto);
  exit(0);
}

exit(99);
