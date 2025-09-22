# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2010-July/044031.html");
  script_oid("1.3.6.1.4.1.25623.1.0.862247");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2010-07-16 10:40:49 +0200 (Fri, 16 Jul 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 16:23:00 +0000 (Fri, 14 Aug 2020)");
  script_xref(name:"FEDORA", value:"2010-11020");
  script_cve_id("CVE-2010-1119", "CVE-2010-1400", "CVE-2010-1778", "CVE-2010-1303", "CVE-2010-1392", "CVE-2010-1396", "CVE-2010-1397", "CVE-2010-1398", "CVE-2010-1412", "CVE-2010-1770", "CVE-2010-1773", "CVE-2010-1774", "CVE-2010-0047", "CVE-2010-0648", "CVE-2010-0656", "CVE-2010-0046", "CVE-2010-0049", "CVE-2010-0050", "CVE-2010-0051", "CVE-2010-0052", "CVE-2010-0054", "CVE-2009-2841", "CVE-2010-1766", "CVE-2010-1772");
  script_name("Fedora Update for qt FEDORA-2010-11020");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC12");
  script_tag(name:"affected", value:"qt on Fedora 12");
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

if(release == "FC12")
{

  if ((res = isrpmvuln(pkg:"qt", rpm:"qt~4.6.3~8.fc12", rls:"FC12")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
