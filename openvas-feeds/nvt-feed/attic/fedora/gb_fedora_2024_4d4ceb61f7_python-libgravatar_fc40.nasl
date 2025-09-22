# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886792");
  script_version("2025-09-22T07:08:28+0000");
  script_cve_id("CVE-2024-4215", "CVE-2024-4216");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-19 13:37:32 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2024-05-27 10:47:52 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for python-libgravatar (FEDORA-2024-4d4ceb61f7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-4d4ceb61f7");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CBWXIRJ3REZLZWJPRQBMERRR3XEXAE4Y");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-libgravatar'
  package(s) announced via the FEDORA-2024-4d4ceb61f7 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Python interface for the Gravatar API.");

  script_tag(name:"affected", value:"'python-libgravatar' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
