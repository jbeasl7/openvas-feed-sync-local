# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-April/msg00005.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870659");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-06 10:44:26 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-0012", "CVE-2011-1179");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2011:0426-01");
  script_name("RedHat Update for spice-xpi RHSA-2011:0426-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice-xpi'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"spice-xpi on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The Simple Protocol for Independent Computing Environments (SPICE) is a
  remote display protocol used in Red Hat Enterprise Linux for viewing
  virtualized guests running on the Kernel-based Virtual Machine (KVM)
  hypervisor, or on Red Hat Enterprise Virtualization Hypervisor.

  The spice-xpi package provides a plug-in that allows the SPICE client to
  run from within Mozilla Firefox.

  An uninitialized pointer use flaw was found in the SPICE Firefox plug-in.
  If a user were tricked into visiting a malicious web page with Firefox
  while the SPICE plug-in was enabled, it could cause Firefox to crash or,
  possibly, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2011-1179)

  It was found that the SPICE Firefox plug-in used a predictable name for one
  of its log files. A local attacker could use this flaw to conduct a
  symbolic link attack, allowing them to overwrite arbitrary files accessible
  to the user running Firefox. (CVE-2011-0012)

  Users of spice-xpi should upgrade to this updated package, which contains
  backported patches to correct these issues. After installing the update,
  Firefox must be restarted for the changes to take effect.");
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

  if ((res = isrpmvuln(pkg:"spice-xpi", rpm:"spice-xpi~2.4~1.el6_0.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-xpi-debuginfo", rpm:"spice-xpi-debuginfo~2.4~1.el6_0.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
