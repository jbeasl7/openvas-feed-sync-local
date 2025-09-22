# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886944");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-25641", "CVE-2024-29894", "CVE-2024-31443", "CVE-2024-31444", "CVE-2024-31445", "CVE-2024-31458", "CVE-2024-31459", "CVE-2024-31460", "CVE-2024-34340", "CVE-2023-49084", "CVE-2023-49085", "CVE-2023-49086", "CVE-2023-49088", "CVE-2023-50250", "CVE-2023-51448");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-18 20:44:22 +0000 (Wed, 18 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-06-07 06:34:39 +0000 (Fri, 07 Jun 2024)");
  script_name("Fedora: Security Advisory for cacti (FEDORA-2024-27a594f71d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-27a594f71d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3MEPZMF3S5AM3CTJOBBHXDOTQWBIFVSU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti'
  package(s) announced via the FEDORA-2024-27a594f71d advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cacti is a complete frontend to RRDTool. It stores all of the
necessary information to create graphs and populate them with
data in a MySQL database. The frontend is completely PHP
driven.");

  script_tag(name:"affected", value:"'cacti' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
