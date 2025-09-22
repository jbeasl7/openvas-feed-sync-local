# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:derby";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801284");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2009-4269");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Derby Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_apache_derby_consolidation.nasl");
  script_mandatory_keys("apache/derby/detected");

  script_tag(name:"summary", value:"Apache Derby is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a weaknesses in the password hash generation algorithm used
  in Derby to store passwords in the database, performs a transformation that reduces the size of the set of
  inputs to SHA-1, which produces a small search space that makes it easier for local and possibly remote
  attackers to crack passwords by generating hash collisions.");

  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to crack passwords by
  generating hash collisions.");

  script_tag(name:"affected", value:"Apache Derby versions before 10.6.1.0.");

  script_tag(name:"solution", value:"Upgrade to Apache Derby version 10.6.1.0 or later.");

  script_xref(name:"URL", value:"http://marcellmajor.com/derbyhash.html");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/DERBY-4483");
  script_xref(name:"URL", value:"http://db.apache.org/derby/releases/release-10.6.1.0.cgi#Fix+for+Security+Bug+CVE-2009-4269");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "10.6.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6.1.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
