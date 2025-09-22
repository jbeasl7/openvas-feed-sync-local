# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:haraka:haraka";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106547");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-27 12:28:21 +0700 (Fri, 27 Jan 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-06 13:11:00 +0000 (Wed, 06 Feb 2019)");

  script_cve_id("CVE-2016-1000282");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Haraka Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("gb_haraka_detect.nasl");
  script_mandatory_keys("haraka/installed");

  script_tag(name:"summary", value:"Haraka is prone to a remote command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Haraka comes with a plugin for processing attachments. Versions before
2.8.9 can be vulnerable to command injection.");

  script_tag(name:"affected", value:"Haraka version 2.8.8 and prior.");

  script_tag(name:"solution", value:"Update to 2.8.9 or later versions.");

  script_xref(name:"URL", value:"https://github.com/outflankbv/Exploits/blob/master/harakiri-CVE-2016-1000282.py");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.8.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.9");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
