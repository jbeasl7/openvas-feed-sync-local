# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886671");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-31497");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-10 14:33:55 +0000 (Fri, 10 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-27 10:44:46 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for libfilezilla (FEDORA-2024-8401d42de6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-8401d42de6");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WMJH7M663BVO3SY6MFAW2FAZWLLXAPRQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libfilezilla'
  package(s) announced via the FEDORA-2024-8401d42de6 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libfilezilla is a small and modern C++ library, offering some basic
functionality to build high-performing, platform-independent programs.");

  script_tag(name:"affected", value:"'libfilezilla' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
