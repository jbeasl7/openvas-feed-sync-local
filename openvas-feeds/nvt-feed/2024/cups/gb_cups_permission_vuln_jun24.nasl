# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openprinting:cups";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152726");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-22 05:18:19 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:N/A:N");

  script_cve_id("CVE-2024-35235");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS < 2.4.9 File Permission Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS is prone to a file permission vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When starting the cupsd server with a Listen configuration item
  pointing to a symbolic link, the cupsd process can be caused to perform an arbitrary chmod of the
  provided argument, providing world-writable access to the target. Given that cupsd is often
  running as root, this can result in the change of permission of any user or system files to be
  world writable. Given the aforementioned Ubuntu AppArmor context, on such systems this
  vulnerability is limited to those files modifiable by the cupsd process. In that specific case it
  was found to be possible to turn the configuration of the Listen argument into full control over
  the cupsd.conf and cups-files.conf configuration files. By later setting the User and Group
  arguments in cups-files.conf, and printing with a printer configured by PPD with a
  'FoomaticRIPCommandLine' argument, arbitrary user and group (not root) command execution could be
  achieved, which can further be used on Ubuntu systems to achieve full root command execution.");

  script_tag(name:"affected", value:"CUPS prior to version 2.4.9.");

  script_tag(name:"solution", value:"Update to version 2.4.9 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/06/11/1");
  script_xref(name:"URL", value:"https://github.com/OpenPrinting/cups/releases/tag/v2.4.9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.9");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
