# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sendio:sendio";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106999");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-07-28 14:49:12 +0700 (Fri, 28 Jul 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-07 15:12:00 +0000 (Mon, 07 Aug 2017)");

  script_cve_id("CVE-2016-10399");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sendio Local File Inclusion Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sendio_detect.nasl");
  script_mandatory_keys("sendio/installed");

  script_tag(name:"summary", value:"Sendio is affected by a Local File Inclusion vulnerability that allows an
unauthenticated, remote attacker to read potentially sensitive system files via a specially crafted URL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Sendio version 8.2.0 and prior.");

  script_tag(name:"solution", value:"Update to version 8.2.1 or later.");

  script_xref(name:"URL", value:"https://sendio.com/support/software-release-history/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "8.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
