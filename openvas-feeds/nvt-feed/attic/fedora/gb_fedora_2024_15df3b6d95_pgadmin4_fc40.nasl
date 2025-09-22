# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886258");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-2044");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-03-25 09:37:13 +0000 (Mon, 25 Mar 2024)");
  script_name("Fedora: Security Advisory for pgadmin4 (FEDORA-2024-15df3b6d95)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-15df3b6d95");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LP2CFN756446YTSXDTWKI5FO5GUGLOGO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pgadmin4'
  package(s) announced via the FEDORA-2024-15df3b6d95 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"pgAdmin is the most popular and feature rich Open Source administration and development
platform for PostgreSQL, the most advanced Open Source database in the world.");

  script_tag(name:"affected", value:"'pgadmin4' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
