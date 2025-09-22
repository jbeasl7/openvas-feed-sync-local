# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-February/015647.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880781");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2009:0308");
  script_cve_id("CVE-2009-0577", "CVE-2008-3640");
  script_name("CentOS Update for cups CESA-2009:0308 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"cups on CentOS 3");
  script_tag(name:"insight", value:"The Common UNIX® Printing System (CUPS) provides a portable printing layer
  for UNIX operating systems.

  The CUPS security advisory, RHSA-2008:0937, stated that it fixed
  CVE-2008-3640 for Red Hat Enterprise Linux 3, 4, and 5. It was discovered
  this flaw was not properly fixed on Red Hat Enterprise Linux 3, however.
  (CVE-2009-0577)

  These new packages contain a proper fix for CVE-2008-3640 on Red Hat
  Enterprise Linux 3. Red Hat Enterprise Linux 4 and 5 already contain the
  appropriate fix for this flaw and do not need to be updated.

  Users of cups should upgrade to these updated packages, which contain a
  backported patch to correct this issue.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.1.17~13.3.56", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.1.17~13.3.56", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.1.17~13.3.56", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
