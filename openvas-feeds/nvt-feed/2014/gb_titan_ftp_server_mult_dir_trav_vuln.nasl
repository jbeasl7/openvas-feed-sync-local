# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:southrivertech:titan_ftp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804400");
  script_version("2023-08-25T05:06:04+0000");
  script_tag(name:"last_modification", value:"2023-08-25 05:06:04 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2014-02-11 16:31:02 +0530 (Tue, 11 Feb 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2014-1841", "CVE-2014-1842", "CVE-2014-1843");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Titan FTP Server < 10.40.1829 Multiple Directory Traversal Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("FTP");
  script_dependencies("gb_southrivertech_titan_ftp_server_consolidation.nasl");
  script_mandatory_keys("titan_ftp_server/detected");

  script_tag(name:"summary", value:"Titan FTP Server is prone to multiple directory traversal
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - It is possible to copy the complete home folder of another user by leveraging a vulnerability on
  the Titan FTP Server Web Interface.

  - It is possible to obtain the complete list of existing users by writing '/../' on the search bar.

  - It is possible to observe the 'Properties' for an existing user home folder. This also allows for
  enumeration of existing users on the system.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to read arbitrary files
  and information on the target system.");

  script_tag(name:"affected", value:"Titan FTP Server version 10.32 Build 1816.");

  script_tag(name:"solution", value:"Update to version 10.40 Build 1829 or later.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125150");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Feb/92");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/titan-ftp-server-1032-build-1816-directory-traversals");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

if (version_is_less_equal(version: version, test_version: "10.32.1816")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.40.1829");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
