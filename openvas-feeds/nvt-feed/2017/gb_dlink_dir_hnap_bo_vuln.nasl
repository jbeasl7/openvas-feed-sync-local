# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106587");
  script_version("2024-08-14T05:05:52+0000");
  script_tag(name:"last_modification", value:"2024-08-14 05:05:52 +0000 (Wed, 14 Aug 2024)");
  script_tag(name:"creation_date", value:"2017-02-14 13:49:17 +0700 (Tue, 14 Feb 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:19:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2016-6563");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DIR Routers HNAP Buffer Overflow Vulnerability (SAP10066)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"Several D-Link DIR Routers are prone to a buffer overflow
  vulnerability in HNAP.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Processing malformed SOAP messages when performing the HNAP
  Login action causes a buffer overflow in the stack. The vulnerable XML fields within the SOAP body
  are: Action, Username, LoginPassword, and Captcha.");

  script_tag(name:"affected", value:"D-Link DIR-885L, DIR-895L, DIR-890L, DIR-880L, DIR-868L,
  DIR-869, DIR-879, DIR-859, DIR-822, DIR-823 and DIR-818L.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10066");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list(
  "cpe:/o:dlink:dir-895l_firmware",
  "cpe:/o:dlink:dir-890l_firmware",
  "cpe:/o:dlink:dir-885l_firmware",
  "cpe:/o:dlink:dir-880l_firmware",
  "cpe:/o:dlink:dir-879_firmware",
  "cpe:/o:dlink:dir-869_firmware",
  "cpe:/o:dlink:dir-868l_firmware",
  "cpe:/o:dlink:dir-859_firmware",
  "cpe:/o:dlink:dir-823_firmware",
  "cpe:/o:dlink:dir-822_firmware",
  "cpe:/o:dlink:dir-818l_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = infos["version"];

if (!hw_version = get_kb_item("d-link/dir/hw_version"))
  exit(0);

if (cpe == "cpe:/o:dlink:dir-885l_firmware" || cpe == "cpe:/o:dlink:dir-895l_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.12", extra: "Hardware revision: " + hw_version);
    security_message(port: 0, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:dlink:dir-890l_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.11b01")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.11b01_beta01_g97i", extra: "Hardware revision: " + hw_version);
    security_message(port: 0, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:dlink:dir-880l_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.08WWb04")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.08WWb04", extra: "Hardware revision: " + hw_version);
    security_message(port: 0, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:dlink:dir-879_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.04")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.04", extra: "Hardware revision: " + hw_version);
    security_message(port: 0, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:dlink:dir-869_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.03")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.03", extra: "Hardware revision: " + hw_version);
    security_message(port: 0, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:dlink:dir-868l_firmware") {
  if (hw_version == "B1" && version_is_less(version: version, test_version: "2.05b01")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.05b01", extra: "Hardware revision: " + hw_version);
    security_message(port: 0, data: report);
    exit(0);
  }

  else if (hw_version == "A1" && version_is_less(version: version, test_version: "1.12WWb04")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.12WWb04", extra: "Hardware revision: " + hw_version);
    security_message(port: 0, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:dlink:dir-859_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.06")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.06", extra: "Hardware revision: " + hw_version);
    security_message(port: 0, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:dlink:dir-823_firmware") {
  if (hw_version == "A1" && version_is_less(version: version, test_version: "1.00WWb06")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.00WWb06", extra: "Hardware revision: " + hw_version);
    security_message(port: 0, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:dlink:dir-822_firmware") {
  if (hw_version == "B1" && version_is_less(version: version, test_version: "2.03WWb01")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.03WWb01", extra: "Hardware revision: " + hw_version);
    security_message(port: 0, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:dlink:dir-818l_firmware") {
  if (hw_version == "B1" && version_is_less(version: version, test_version: "2.05")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.05 beta 08", extra: "Hardware revision: " + hw_version);
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
