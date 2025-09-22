# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-August/018823.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881473");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-24 09:55:57 +0530 (Fri, 24 Aug 2012)");
  script_cve_id("CVE-2012-3445");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2012:1202");
  script_name("CentOS Update for libvirt CESA-2012:1202 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"libvirt on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
  virtualization capabilities of Linux and other operating systems. In
  addition, libvirt provides tools for remote management of virtualized
  systems.

  A flaw was found in libvirtd's RPC call handling. An attacker able to
  establish a read-only connection to libvirtd could trigger this flaw with a
  specially-crafted RPC command that has the number of parameters set to 0,
  causing libvirtd to access invalid memory and crash. (CVE-2012-3445)

  This update also fixes the following bugs:

  * Previously, repeatedly migrating a guest between two machines while using
  the tunnelled migration could cause the libvirt daemon to lock up
  unexpectedly. The bug in the code for locking remote drivers has been fixed
  and repeated tunnelled migrations of domains now work as expected.
  (BZ#847946)

  * Previously, when certain system locales were used by the system, libvirt
  could issue incorrect commands to the hypervisor. This bug has been fixed
  and the libvirt library and daemon are no longer affected by the choice of
  the user locale. (BZ#847959)

  All users of libvirt are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. After installing
  the updated packages, libvirtd will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.9.10~21.el6_3.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.9.10~21.el6_3.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.9.10~21.el6_3.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.9.10~21.el6_3.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~0.9.10~21.el6_3.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
