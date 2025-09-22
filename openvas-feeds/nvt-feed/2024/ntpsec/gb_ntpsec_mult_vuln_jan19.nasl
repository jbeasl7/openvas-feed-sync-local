# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntpsec:ntpsec";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114367");
  script_version("2024-02-20T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-20 09:23:30 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-16 05:29:01 +0000 (Wed, 16 Jan 2019)");

  script_cve_id("CVE-2019-6442", "CVE-2019-6443", "CVE-2019-6444", "CVE-2019-6445");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NTPsec < 1.1.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("ntp_open.nasl");
  script_mandatory_keys("ntpsec/detected");

  script_tag(name:"summary", value:"NTPsec is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2019-6442: Authenticated out-of-bounds write

  - CVE-2019-6443, CVE-2019-6444: Out-of-bounds read

  - CVE-2019-6445: Authenticated NULL pointer exception");

  script_tag(name:"affected", value:"NTPsec versions prior to 1.1.3.");

  script_tag(name:"solution", value:"Update to version 1.1.3 or later.");

  script_xref(name:"URL", value:"https://dumpco.re/blog/ntpsec-bugs");
  script_xref(name:"URL", value:"https://dumpco.re/bugs/ntpsec-oobread1");
  script_xref(name:"URL", value:"https://dumpco.re/bugs/ntpsec-oobread2");
  script_xref(name:"URL", value:"https://dumpco.re/bugs/ntpsec-authed-npe");
  script_xref(name:"URL", value:"https://dumpco.re/bugs/ntpsec-authed-oobwrite");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "1.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.3", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
