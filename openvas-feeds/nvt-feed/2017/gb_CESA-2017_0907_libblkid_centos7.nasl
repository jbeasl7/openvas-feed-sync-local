# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882691");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2017-04-14 06:30:18 +0200 (Fri, 14 Apr 2017)");
  script_cve_id("CVE-2017-2616");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:26:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for libblkid CESA-2017:0907 centos7");
  script_tag(name:"summary", value:"Check the version of libblkid");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The util-linux packages contain a large
variety of low-level system utilities that are necessary for a Linux system to
function. Among others, these include the fdisk configuration tool and the
login program.

Security Fix(es):

  * A race condition was found in the way su handled the management of child
processes. A local authenticated attacker could use this flaw to kill other
processes with root privileges under specific conditions. (CVE-2017-2616)

Red Hat would like to thank Tobias Stockmann for reporting this issue.

Bug Fix(es):

  * The 'findmnt --target  path ' command prints all file systems where the
mount point directory is  path. Previously, when used in the chroot
environment, 'findmnt --target  path ' incorrectly displayed all mount
points. The command has been fixed so that it now checks the mount point
path and returns information only for the relevant mount point.
(BZ#1414481)");
  script_tag(name:"affected", value:"libblkid on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:0907");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-April/022376.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"libblkid", rpm:"libblkid~2.23.2~33.el7_3.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libblkid-devel", rpm:"libblkid-devel~2.23.2~33.el7_3.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmount", rpm:"libmount~2.23.2~33.el7_3.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmount-devel", rpm:"libmount-devel~2.23.2~33.el7_3.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libuuid", rpm:"libuuid~2.23.2~33.el7_3.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libuuid-devel", rpm:"libuuid-devel~2.23.2~33.el7_3.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"util-linux", rpm:"util-linux~2.23.2~33.el7_3.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"uuidd", rpm:"uuidd~2.23.2~33.el7_3.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
