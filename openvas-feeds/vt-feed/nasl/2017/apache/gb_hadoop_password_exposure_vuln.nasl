# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:hadoop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112036");
  script_version("2026-01-28T05:49:43+0000");
  script_cve_id("CVE-2016-3086");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-11 18:25:00 +0000 (Mon, 11 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-06-27 20:31:53 +0530 (Tue, 27 Jun 2017)");
  script_name("Apache Hadoop Password Exposure Vulnerability (Jan 2017)");

  script_tag(name:"summary", value:"Apache Hadoop is prone to a password exposure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The YARN NodeManager in Apache Hadoop can leak the password for credential store provider used by the NodeManager to YARN Applications.");

  script_tag(name:"impact", value:"By using the CredentialProvider feature to encrypt passwords used in
  NodeManager configs, it may be possible for any Container launched by
  that NodeManager to gain access to the encryption password. The other
  passwords themselves are not directly exposed.");

  script_tag(name:"affected", value:"All versions of Hadoop 2.6.x before 2.6.5 and 2.7.x before 2.7.3.");

  script_tag(name:"solution", value:"Upgrade to Apache Hadoop version 2.6.5 or 2.7.3 or
  later or set the permission of the jceks file appropriately to restrict access from unauthorized users.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://mail-archives.apache.org/mod_mbox/hadoop-general/201701.mbox/%3C0ed32746-5a53-9051-5877-2b1abd88beb6%40apache.org%3E");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_http_detect.nasl");
  script_mandatory_keys("apache/hadoop/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range_exclusive(version:vers, test_version_lo:"2.6.0", test_version_up:"2.6.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.6.5");
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range_exclusive(version:vers, test_version_lo:"2.7.0", test_version_up:"2.7.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.7.3");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
