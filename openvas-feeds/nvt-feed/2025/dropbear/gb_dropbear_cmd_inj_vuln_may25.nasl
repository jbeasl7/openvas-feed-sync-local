# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dropbear_ssh_project:dropbear_ssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154473");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-12 02:29:03 +0000 (Mon, 12 May 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2025-47203");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Dropbear < 2025.88 Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dropbear_consolidation.nasl");
  script_mandatory_keys("dropbear_ssh/detected");

  script_tag(name:"summary", value:"Dropbear is prone to a command injection vulnerability in
  dbclient.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"dbclient hostname arguments with a comma (for multihop) are
  passed to the shell which could result in running arbitrary shell commands locally. That could be
  a security issue in situations where dbclient is passed untrusted hostname arguments.");

  script_tag(name:"affected", value:"Dropbear version 2025.87 and prior.");

  script_tag(name:"solution", value:"Update to version 2025.88 or later.");

  script_xref(name:"URL", value:"https://github.com/mkj/dropbear/blob/master/CHANGES");
  script_xref(name:"URL", value:"https://lists.ucc.gu.uwa.edu.au/pipermail/dropbear/2025q2/002385.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/05/09/4");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2025.88")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2025.88", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
