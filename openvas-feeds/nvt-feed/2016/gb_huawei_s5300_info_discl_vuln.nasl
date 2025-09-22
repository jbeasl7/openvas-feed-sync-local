# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106157");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-29 09:30:37 +0700 (Fri, 29 Jul 2016)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-21 17:29:00 +0000 (Thu, 21 Jan 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_cve_id("CVE-2015-8675");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei S5300 Campus Series Switches information Disclosure Vulnerability (huawei-sa-20160112-01-switch)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Huawei S5300 Campus Series switches are prone to a local information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When uploading files to some directory, the user needs to enter the
  username and password. However, the system does not mask passwords. As a result, the password entered is
  displayed in plain text, leading to password leaks.");

  script_tag(name:"impact", value:"Physically proximate attackers may obtain sensitive password information
  by reading the display.");

  script_tag(name:"affected", value:"Versions prior to V200R005SPH008.");

  script_tag(name:"solution", value:"Upgrade to Version V200R005SPH008 or later.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20160112-01-switch-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("revisions-lib.inc");

cpe_list = make_list("cpe:/o:huawei:s5300_firmware"
                     );

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

version = toupper(version);

if (revcomp(a: version, b: "V200R005SPH008") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "V200R005SPH008");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
