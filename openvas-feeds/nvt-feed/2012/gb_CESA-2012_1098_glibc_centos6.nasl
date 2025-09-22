# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018753.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881067");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:00:11 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-3404", "CVE-2012-3405", "CVE-2012-3406");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2012:1098");
  script_name("CentOS Update for glibc CESA-2012:1098 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"glibc on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The glibc packages provide the standard C and standard math libraries used
  by multiple programs on the system. Without these libraries, the Linux
  system cannot function properly.

  Multiple errors in glibc's formatted printing functionality could allow an
  attacker to bypass FORTIFY_SOURCE protections and execute arbitrary code
  using a format string flaw in an application, even though these protections
  are expected to limit the impact of such flaws to an application abort.
  (CVE-2012-3404, CVE-2012-3405, CVE-2012-3406)

  This update also fixes the following bug:

  * A programming error caused an internal array of nameservers to be only
  partially initialized when the /etc/resolv.conf file contained IPv6
  nameservers. Depending on the contents of a nearby structure, this could
  cause certain applications to terminate unexpectedly with a segmentation
  fault. The programming error has been fixed, which restores proper behavior
  with IPv6 nameservers listed in the /etc/resolv.conf file. (BZ#837026)

  All users of glibc are advised to upgrade to these updated packages, which
  contain backported patches to fix these issues.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.12~1.80.el6_3.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.12~1.80.el6_3.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.12~1.80.el6_3.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.12~1.80.el6_3.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.12~1.80.el6_3.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.12~1.80.el6_3.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.12~1.80.el6_3.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
