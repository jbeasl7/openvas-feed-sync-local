# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2012-April/079111.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864178");
  script_version("2023-06-23T16:09:17+0000");
  script_tag(name:"last_modification", value:"2023-06-23 16:09:17 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"creation_date", value:"2012-04-26 10:33:10 +0530 (Thu, 26 Apr 2012)");
  script_cve_id("CVE-2012-2123", "CVE-2012-2121", "CVE-2012-2119", "CVE-2012-1601",
                "CVE-2012-1568", "CVE-2012-1179", "CVE-2012-1146", "CVE-2012-1097",
                "CVE-2012-1090", "CVE-2011-4086", "CVE-2012-0056", "CVE-2011-4127",
                "CVE-2012-0045", "CVE-2011-4347", "CVE-2011-4622", "CVE-2011-4131",
                "CVE-2011-4132", "CVE-2011-4097", "CVE-2011-4077", "CVE-2011-3347",
                "CVE-2011-1083", "CVE-2011-1161", "CVE-2011-1162", "CVE-2011-3191",
                "CVE-2011-2905");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 10:59:00 +0000 (Fri, 31 Jul 2020)");
  script_xref(name:"FEDORA", value:"2012-6406");
  script_name("Fedora Update for kernel FEDORA-2012-6406");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC15");
  script_tag(name:"affected", value:"kernel on Fedora 15");
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

if(release == "FC15")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.43.2~6.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
