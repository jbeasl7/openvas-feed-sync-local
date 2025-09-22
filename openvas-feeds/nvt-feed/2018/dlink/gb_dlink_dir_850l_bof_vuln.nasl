# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-850l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813008");
  script_version("2023-11-21T05:05:52+0000");
  script_tag(name:"last_modification", value:"2023-11-21 05:05:52 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"creation_date", value:"2018-03-08 16:47:29 +0530 (Thu, 08 Mar 2018)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 20:19:00 +0000 (Wed, 08 Nov 2023)");

  script_cve_id("CVE-2017-3193");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DIR-850L 'CVE-2017-3193' Stack-Based Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-850L devices are prone to a buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient validation of user-supplied
  input in the web administration interface of the affected system.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote attackers to conduct
  arbitrary code execution. Failed exploit attempts will likely cause a denial-of-service condition.");

  script_tag(name:"affected", value:"D-Link DIR-850L, firmware versions 1.14B07, 2.07.B05 and possibly
  others.");

  script_tag(name:"solution", value:"Update to version 1.14B07 h2ab BETA1 or 2.07B05 h1ke BETA1,
  depending on the device's hardware revision.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/305448");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96747");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=52967");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

# cpe:/o:dlink:dir-850l_firmware:2.06
if (!fw_vers = get_app_version(cpe: CPE, port: port))
  exit(0);

# e.g. B1
if (!hw_vers = get_kb_item("d-link/dir/hw_version"))
  exit(0);

hw_vers = toupper(hw_vers);
fw_vers = toupper(fw_vers);

if (hw_vers =~ "^A" && version_is_less_equal(version: fw_vers, test_version: "1.14B07"))
  fix  = "1.14B07 h2ab BETA1";

if (hw_vers =~ "^B" && version_is_less_equal(version: fw_vers, test_version: "2.07B05"))
  fix  = "2.07B05 h1ke BETA1";

if(fix) {
  report = report_fixed_ver(installed_version: fw_vers, fixed_version:fix, extra: "Hardware revision: " + hw_vers);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
