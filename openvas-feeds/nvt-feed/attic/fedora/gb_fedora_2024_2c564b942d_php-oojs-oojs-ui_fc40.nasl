# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886840");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2023-3550", "CVE-2023-45360", "CVE-2023-45362", "CVE-2023-51704", "CVE-2024-34507", "CVE-2024-34506", "CVE-2024-34500", "CVE-2024-34502");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-25 16:15:14 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-05-27 10:49:04 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for php-oojs-oojs-ui (FEDORA-2024-2c564b942d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-2c564b942d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FU2FGUXXK6TMV6R52VRECLC6XCSQQISY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-oojs-oojs-ui'
  package(s) announced via the FEDORA-2024-2c564b942d advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OOjs UI (Object-Oriented JavaScript  User Interface) is a library that allows
developers to rapidly create front-end web applications that operate
consistently across a multitude of browsers.");

  script_tag(name:"affected", value:"'php-oojs-oojs-ui' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
