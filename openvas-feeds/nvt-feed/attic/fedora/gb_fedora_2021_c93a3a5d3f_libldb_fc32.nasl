# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818223");
  script_version("2024-06-13T05:05:46+0000");
  script_cve_id("CVE-2020-27840", "CVE-2021-20277");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 19:46:00 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-04-10 03:04:04 +0000 (Sat, 10 Apr 2021)");
  script_name("Fedora: Security Advisory for libldb (FEDORA-2021-c93a3a5d3f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-c93a3a5d3f");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GPOVXAJVNNS6GC2OI22JBMLFMGT2IEXY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libldb'
  package(s) announced via the FEDORA-2021-c93a3a5d3f advisory.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An extensible library that implements an LDAP like API to access remote LDAP
servers, or use local tdb databases.");

  script_tag(name:"affected", value:"'libldb' package(s) on Fedora 32.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);