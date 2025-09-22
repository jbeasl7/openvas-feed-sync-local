# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:hadoop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812673");
  script_version("2024-10-23T05:05:59+0000");
  script_cve_id("CVE-2017-15718");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-01-25 11:40:52 +0530 (Thu, 25 Jan 2018)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Hadoop 2.7.3 - 2.7.4 YARN NodeManager Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");

  script_tag(name:"summary", value:"Apache Hadoop is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as if the CredentialProvider feature is used to
  encrypt passwords used in NodeManager configs, it may be possible for any Container launched by
  that NodeManager to gain access to the encryption password. The other passwords themselves are not
  directly exposed.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to gain
  access to the password for credential store provider used by the NodeManager to YARN
  Applications.");

  script_tag(name:"affected", value:"Apache Hadoop versions 2.7.3 and 2.7.4.");

  script_tag(name:"solution", value:"Update to version 2.7.5 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/dzz49w26ypg7no8s647rhnmorwo88bh5");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"2.7.3", test_version2:"2.7.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.7.5", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
