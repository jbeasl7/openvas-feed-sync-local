# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:couchdb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112221");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2018-02-13 09:02:26 +0100 (Tue, 13 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-14 12:13:00 +0000 (Wed, 14 Mar 2018)");

  script_cve_id("CVE-2016-8742");

  script_name("CouchDB 2.0.0 Privilege Escalation Vulnerability - Windows");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_apache_couchdb_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/couchdb/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache CouchDB is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Windows installer that the Apache CouchDB team provides is
  vulnerable to local privilege escalation. All files in the install inherit the file permissions of
  the parent directory and therefore a non-privileged user can substitute any executable for the
  nssm.exe service launcher, or CouchDB batch or binary files. A subsequent service or server restart
  will then run that binary with administrator privilege.");

  script_tag(name:"affected", value:"Apache CouchDB version 2.0.0 on Windows");

  script_tag(name:"solution", value:'Update to version 2.0.0.1 or later.

  NOTE:

  If an upgrade cannot be performed, the following steps will secure an existing CouchDB 2.0.0
  installation:

  1. In Windows Explorer, navigate to the CouchDB installation folder. Right click on the folder and
  select Properties.

  2. In the Properties window, select the Security tab, and click on the Advanced button.

  3. In the Advanced Security Settings window, click the Change Permissions... button.

  4. Ensure only the following settings are listed, removing any other entries:

  - Allow - Users - Read & Execute

  - Allow - SYSTEM - Full control

  - Allow - Administrators - Full control

  5. Check the "Replace all child object permissions with inheritable permissions from this object."

  6. Click OK three times to close all dialog boxes.');

  script_xref(name:"URL", value:"http://mail-archives.apache.org/mod_mbox/couchdb-dev/201612.mbox/%3C825F65E1-0E5F-4E1F-8053-CF2C6200C526%40apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_equal(version: version, test_version: "2.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.0.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

