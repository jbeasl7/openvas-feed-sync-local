# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147626");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"creation_date", value:"2022-02-14 04:53:48 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-07 20:03:00 +0000 (Mon, 07 Mar 2022)");

  script_cve_id("CVE-2021-46668");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB DoS Vulnerability (MDEV-25787) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Databases");

  script_tag(name:"summary", value:"MariaDB is prone to a denial of service (DoS) vulnerability.

  This VT has been deprecated as a duplicate of the following VT:

  MariaDB DoS Vulnerability (MDEV-25787) - Linux (OID: 1.3.6.1.4.1.25623.1.0.147579)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MariaDB allows an application crash via certain long SELECT
  DISTINCT statements that improperly interact with storage-engine resource limitations for
  temporary data structures.");

  script_tag(name:"affected", value:"MariaDB versions prior to 10.2.43, 10.3.x prior to 10.3.34,
  10.4.x prior to 10.4.24, 10.5.x prior to 10.5.15, 10.6.x prior to 10.6.7 and 10.7.x prior to
  10.7.3.");

  script_tag(name:"solution", value:"Update to version 10.2.43, 10.3.34, 10.4.24, 10.5.15, 10.6.7,
  10.7.3 or later.");

  script_xref(name:"URL", value:"https://jira.mariadb.org/browse/MDEV-25787");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/security/#full-list-of-cves-fixed-in-mariadb");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
