# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887396");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-0760", "CVE-2024-1737", "CVE-2024-1975", "CVE-2024-4076");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-23 15:15:03 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-08-17 04:04:01 +0000 (Sat, 17 Aug 2024)");
  script_name("Fedora: Security Advisory for bind (FEDORA-2024-ef8a7031e7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-ef8a7031e7");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LKRSR4XX446LTUNFB7J4U4WA3TTJKJV2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the FEDORA-2024-ef8a7031e7 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"BIND (Berkeley Internet Name Domain) is an implementation of the DNS
(Domain Name System) protocols");

  script_tag(name:"affected", value:"'bind' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
