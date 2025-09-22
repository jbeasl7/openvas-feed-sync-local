# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00061.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50829");
  script_oid("1.3.6.1.4.1.25623.1.0.870923");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-02-22 10:01:47 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2011-4355");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2013:0522-02");
  script_name("RedHat Update for gdb RHSA-2013:0522-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"gdb on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The GNU Debugger (GDB) allows debugging of programs written in C, C++,
  Java, and other languages by executing them in a controlled fashion and
  then printing out their data.

  GDB tried to auto-load certain files (such as GDB scripts, Python scripts,
  and a thread debugging library) from the current working directory when
  debugging programs. This could result in the execution of arbitrary code
  with the user's privileges when GDB was run in a directory that has
  untrusted content. (CVE-2011-4355)

  With this update, GDB no longer auto-loads files from the current directory
  and only trusts certain system directories by default. The list of trusted
  directories can be viewed and modified using the show auto-load safe-path
  and set auto-load safe-path GDB commands. Refer to the GDB manual, linked
  to in the References, for further information.

  This update also fixes the following bugs:

  * When a struct member was at an offset greater than 256 MB, the resulting
  bit position within the struct overflowed and caused an invalid memory
  access by GDB. With this update, the code has been modified to ensure that
  GDB can access such positions. (BZ#795424)

  * When a thread list of the core file became corrupted, GDB did not print
  this list but displayed the Cannot find new threads: generic error error
  message instead. With this update, GDB has been modified and it now prints
  the thread list of the core file as expected. (BZ#811648)

  * GDB did not properly handle debugging of multiple binaries with the
  same build ID. This update modifies GDB to use symbolic links created for
  particular binaries so that debugging of binaries that share a build ID
  now proceeds as expected. Debugging of live programs and core files is
  now more user-friendly. (BZ#836966)

  All users of gdb are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.");
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

  if ((res = isrpmvuln(pkg:"gdb", rpm:"gdb~7.2~60.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdb-debuginfo", rpm:"gdb-debuginfo~7.2~60.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdb-gdbserver", rpm:"gdb-gdbserver~7.2~60.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
