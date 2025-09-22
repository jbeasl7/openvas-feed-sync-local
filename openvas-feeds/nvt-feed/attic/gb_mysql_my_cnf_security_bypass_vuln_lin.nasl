# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809331");
  script_version("2025-01-17T15:39:18+0000");
  script_cve_id("CVE-2016-6662");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92912");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 17:41:00 +0000 (Mon, 03 Jun 2019)");
  script_tag(name:"creation_date", value:"2016-09-26 12:24:08 +0530 (Mon, 26 Sep 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle MySQL 'my.conf' Security Bypass Vulnerability - Linux");

  script_tag(name:"summary", value:"Oracle MySQL is prone to a security bypass vulnerability.

  This VT has been deprecated and replaced by the VT 'Oracle MySQL Security Updates (oct2016-2881722) 09 - Linux'
  (OID: 1.3.6.1.4.1.25623.1.0.809387).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to datadir is writable by the mysqld server,
  and a user that can connect to MySQL can create 'my.cnf' in the datadir using 'SELECT ... OUTFILE'.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local users to execute
  arbitrary code with root privileges by setting malloc_lib.");

  script_tag(name:"affected", value:"Oracle MySQL before 5.5.52, 5.6.x
  before 5.6.33, and 5.7.x before 5.7.15.");

  script_tag(name:"solution", value:"Upgrade to Oracle MySQL 5.5.52,
  or 5.6.33, or 5.7.15, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
