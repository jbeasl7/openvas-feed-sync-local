# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:buffalo:wzr-1750dhp2_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140996");
  script_version("2025-05-20T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-20 05:40:25 +0000 (Tue, 20 May 2025)");
  script_tag(name:"creation_date", value:"2018-04-18 14:09:34 +0700 (Wed, 18 Apr 2018)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-16 12:53:00 +0000 (Wed, 16 May 2018)");

  script_cve_id("CVE-2018-0554", "CVE-2018-0555", "CVE-2018-0556");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Buffalo WZR-1750DHP2 < 2.31 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_buffalo_airstation_detect.nasl");
  script_mandatory_keys("buffalo/airstation/detected");

  script_tag(name:"summary", value:"Buffalo WZR-1750DHP2 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-0554: Authentication bypass and execution of arbitrary commands on the device via
  unspecified vectors

  - CVE-2018-0555: Arbitrary code execution via a specially crafted file

  - CVE-2018-0556: Arbitrary OS commands execution via unspecified vectors");

  script_tag(name:"affected", value:"Buffalo WZR-1750DHP2 firmware version 2.30 and prior.");

  script_tag(name:"solution", value:"Update to firmware version 2.31 or later.");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN93397125/index.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "2.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.31");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
