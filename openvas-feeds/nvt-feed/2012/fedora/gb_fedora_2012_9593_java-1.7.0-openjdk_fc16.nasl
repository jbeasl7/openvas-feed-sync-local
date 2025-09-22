# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2012-June/082422.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864471");
  script_version("2024-07-17T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-06-19 09:38:13 +0530 (Tue, 19 Jun 2012)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-1711", "CVE-2012-1717", "CVE-2012-1716", "CVE-2012-1713",
                "CVE-2012-1719", "CVE-2012-1718", "CVE-2012-1723", "CVE-2012-1724",
                "CVE-2012-1725", "CVE-2012-0497", "CVE-2011-3571", "CVE-2012-0503",
                "CVE-2012-0505", "CVE-2012-0502", "CVE-2011-3563", "CVE-2011-5035",
                "CVE-2012-0501", "CVE-2012-0506", "CVE-2011-3547", "CVE-2011-3548",
                "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3544", "CVE-2011-3521",
                "CVE-2011-3554", "CVE-2011-3389", "CVE-2011-3558", "CVE-2011-3556",
                "CVE-2011-3557", "CVE-2011-3560");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:38:00 +0000 (Tue, 16 Jul 2024)");
  script_xref(name:"FEDORA", value:"2012-9593");
  script_name("Fedora Update for java-1.7.0-openjdk FEDORA-2012-9593");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.7.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC16");
  script_tag(name:"affected", value:"java-1.7.0-openjdk on Fedora 16");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.3~2.2.1.fc16.7", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
