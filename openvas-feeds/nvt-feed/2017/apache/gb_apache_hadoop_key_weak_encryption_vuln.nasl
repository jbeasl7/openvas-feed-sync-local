# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:hadoop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811969");
  script_version("2024-03-04T05:10:24+0000");
  script_cve_id("CVE-2012-4449");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-04 05:10:24 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-21 15:53:00 +0000 (Tue, 21 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-11-08 11:34:54 +0530 (Wed, 08 Nov 2017)");
  script_name("Apache Hadoop Weak Key Encryption Vulnerability");

  script_tag(name:"summary", value:"Apache Hadoop is prone to a weak key encryption vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in an unknown
  function of the component 'Kerberos Security Feature'.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to crack secret keys via a brute-force attack.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"Apache Hadoop before 0.23.4, 1.x before 1.0.4,
  and 2.x before 2.0.2");

  script_tag(name:"solution", value:"Upgrade to Apache Hadoop version 0.23.4 or
  1.0.4 or 2.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/onrj4hblqbxdx0wpkfr857fl40lfgpc8");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version =~ "^2\.0" && version_is_less(version:version, test_version:"2.0.2")) {
  fix = "2.0.2";
}

else if(version_in_range(version:version, test_version:"1.0", test_version2:"1.0.3")) {
  fix = "1.0.4";
}

else if(version_is_less(version:version, test_version:"0.23.4")) {
  fix = "0.23.4";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
