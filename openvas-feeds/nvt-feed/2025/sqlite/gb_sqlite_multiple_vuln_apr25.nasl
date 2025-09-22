# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sqlite:sqlite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128120");
  script_version("2025-08-04T05:47:09+0000");
  script_tag(name:"last_modification", value:"2025-08-04 05:47:09 +0000 (Mon, 04 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-04-15 12:28:38 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-01 18:29:43 +0000 (Fri, 01 Aug 2025)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2025-29087", "CVE-2025-3277");

  script_name("SQLite 3.44.0 - 3.49.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_sqlite_ssh_login_detect.nasl");
  script_mandatory_keys("sqlite/detected");

  script_tag(name:"summary", value:"SQLite is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2025-29087: The concat_ws() SQL function can cause memory to be written
  beyond the end of a malloc-allocated buffer. If the separator argument is attacker-controlled and
  has a large string (e.g., 2MB or more), an integer overflow occurs in calculating the size of the
  result buffer, and thus malloc may not allocate enough memory.

  - CVE-2025-3277: An integer overflow can be triggered in SQLite `concat_ws()`function.
  The resulting, truncated integer is then used to allocate a buffer. When SQLite then
  writes the resulting string to the buffer, it uses the original, untruncated size and thus a
  wild Heap Buffer overflow of size ~4GB can be triggered. This can result in arbitrary
  code execution.");

  script_tag(name:"affected", value:"SQLite versions 3.44.0 through 3.49.0.");

  script_tag(name:"solution", value:"Update to version 3.49.1 or later.");

  script_xref(name:"URL", value:"https://sqlite.org/cves.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "3.44.0", test_version_up: "3.49.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.49.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
