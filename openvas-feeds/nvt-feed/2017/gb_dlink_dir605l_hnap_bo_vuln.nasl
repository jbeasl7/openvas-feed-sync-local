# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-605l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112145");
  script_version("2023-11-21T05:05:52+0000");
  script_tag(name:"last_modification", value:"2023-11-21 05:05:52 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-12-04 13:02:20 +0100 (Mon, 04 Dec 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 21:17:00 +0000 (Wed, 08 Nov 2023)");

  script_cve_id("CVE-2017-17065");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DIR-605L Rev. B < 2.11betaB06_hbrf HNAP Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-605L Rev. B router is prone to a HNAP buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It is possible to cause the router to crash and reboot when
  sending large buffers in the HTTP Basic Authentication password field. If a large enough buffer was
  sent, the next request to the web server would cause the reboot.");

  script_tag(name:"impact", value:"This issue could cause a possible condition - once crashed - to
  open other attack vectors for further exploitation.");

  script_tag(name:"affected", value:"D-Link DIR-605L Rev. B routers with firmware prior to
  version 2.11betaB06_hbrf.");

  script_tag(name:"solution", value:"Upgrade to version 2.11betaB06_hbrf or later.");

  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-605L/REVB/DIR-605L_REVB_FIRMWARE_PATCH_NOTES_2.11betaB06_HBRF_EN.pdf");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

# cpe:/o:dlink:dir-605l_firmware:2.06
if (!fw_vers = get_app_version(cpe: CPE, port: port))
  exit(0);

# e.g. B1
if (!hw_vers = get_kb_item("d-link/dir/hw_version"))
  exit(0);

hw_vers = toupper(hw_vers);

if (hw_vers =~ "^B" && version_is_less(version: fw_vers, test_version: "2.11")) {
  report = report_fixed_ver(installed_version: fw_vers, fixed_version: "2.11betaB06_hbrf", extra: "Hardware revision: " + hw_vers);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
