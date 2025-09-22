# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871398");
  script_version("2024-03-21T05:06:54+0000");
  script_cve_id("CVE-2014-8169");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-07-23 06:25:07 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for autofs RHSA-2015:1344-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'autofs'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The autofs utility controls the operation of the automount daemon. The
daemon automatically mounts file systems when in use and unmounts them when
they are not busy.

It was found that program-based automounter maps that used interpreted
languages such as Python would use standard environment variables to locate
and load modules of those languages. A local attacker could potentially use
this flaw to escalate their privileges on the system. (CVE-2014-8169)

Note: This issue has been fixed by adding the 'AUTOFS_' prefix to the
affected environment variables so that they are not used to subvert the
system. A configuration option ('force_standard_program_map_env') to
override this prefix and to use the environment variables without the
prefix has been added. In addition, warnings have been added to the manual
page and to the installed configuration file. Now, by default the standard
variables of the program map are provided only with the prefix added to
its name.

Red Hat would like to thank the Georgia Institute of Technology for
reporting this issue.

Bug fixes:

  * If the 'ls *' command was executed before a valid mount, the autofs
program failed on further mount attempts inside the mount point, whether
the mount point was valid or not. While attempting to mount, the 'ls *'
command of the root directory of an indirect mount was executed, which
led to an attempt to mount '*', causing it to be added to the negative
map entry cache. This bug has been fixed by checking for and not adding
'*' while updating the negative map entry cache. (BZ#1163957)

  * The autofs program by design did not mount host map entries that were
duplicate exports in an NFS server export list. The duplicate entries in a
multi-mount map entry were recognized as a syntax error and autofs refused
to perform mounts when the duplicate entries occurred. Now, autofs has been
changed to continue mounting the last seen instance of the duplicate entry
rather than fail, and to report the problem in the log files to alert the
system administrator. (BZ#1124083)

  * The autofs program did not recognize the yp map type in the master map.
This was caused by another change in the master map parser to fix a problem
with detecting the map format associated with mapping the type in the
master map. The change led to an incorrect length for the type comparison
of yp maps that resulted in a match operation failure. This bug has been
fixed by correcting the length which is used for the comparison.
(BZ#1153130)

  * The autofs program did ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"autofs on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:1344-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00024.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"autofs", rpm:"autofs~5.0.5~113.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"autofs-debuginfo", rpm:"autofs-debuginfo~5.0.5~113.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
