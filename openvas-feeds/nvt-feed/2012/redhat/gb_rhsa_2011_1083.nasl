# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-July/msg00018.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870720");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-06 10:53:18 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2010-3879", "CVE-2011-0541", "CVE-2011-0542", "CVE-2011-0543");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_xref(name:"RHSA", value:"2011:1083-01");
  script_name("RedHat Update for fuse RHSA-2011:1083-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fuse'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"fuse on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"FUSE (Filesystem in Userspace) can implement a fully functional file system
  in a user-space program. These packages provide the mount utility,
  fusermount, the tool used to mount FUSE file systems.

  Multiple flaws were found in the way fusermount handled the mounting and
  unmounting of directories when symbolic links were present. A local user in
  the fuse group could use these flaws to unmount file systems, which they
  would otherwise not be able to unmount and that were not mounted using
  FUSE, via a symbolic link attack. (CVE-2010-3879, CVE-2011-0541,
  CVE-2011-0542, CVE-2011-0543)

  Note: The util-linux-ng RHBA-2011:0699 update must also be installed to
  fully correct the above flaws.

  All users should upgrade to these updated packages, which contain
  backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"fuse", rpm:"fuse~2.8.3~3.el6_1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fuse-debuginfo", rpm:"fuse-debuginfo~2.8.3~3.el6_1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fuse-devel", rpm:"fuse-devel~2.8.3~3.el6_1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fuse-libs", rpm:"fuse-libs~2.8.3~3.el6_1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
