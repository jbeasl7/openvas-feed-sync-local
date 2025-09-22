# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-July/msg00023.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870457");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-07-22 14:44:51 +0200 (Fri, 22 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2011:1005-01");
  script_cve_id("CVE-2007-3852");
  script_name("RedHat Update for sysstat RHSA-2011:1005-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sysstat'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"sysstat on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The sysstat package contains a set of utilities which enable system
  monitoring of disks, network, and other I/O activity.

  It was found that the sysstat initscript created a temporary file in an
  insecure way. A local attacker could use this flaw to create arbitrary
  files via a symbolic link attack. (CVE-2007-3852)

  This update fixes the following bugs:

  * On systems under heavy load, the sadc utility would sometimes output the
  following error message if a write() call was unable to write all of the
  requested input:

  'Cannot write data to system activity file: Success.'

  In this updated package, the sadc utility tries to write the remaining
  input, resolving this issue. (BZ#454617)

  * On the Itanium architecture, the 'sar -I' command provided incorrect
  information about the interrupt statistics of the system. With this update,
  the 'sar -I' command has been disabled for this architecture, preventing
  this bug. (BZ#468340)

  * Previously, the 'iostat -n' command used invalid data to create
  statistics for read and write operations. With this update, the data source
  for these statistics has been fixed, and the iostat utility now returns
  correct information. (BZ#484439)

  * The 'sar -d' command used to output invalid data about block devices.
  With this update, the sar utility recognizes disk registration and disk
  overflow statistics properly, and only correct and relevant data is now
  displayed. (BZ#517490)

  * Previously, the sar utility set the maximum number of days to be logged
  in one month too high. Consequently, data from a month was appended to
  data from the preceding month. With this update, the maximum number of days
  has been set to 25, and data from a month now correctly replaces data from
  the preceding month. (BZ#578929)

  * In previous versions of the iostat utility, the number of NFS mount
  points was hard-coded. Consequently, various issues occurred while iostat
  was running and NFS mount points were mounted or unmounted. Certain values
  in iostat reports overflowed and some mount points were not reported at
  all. With this update, iostat properly recognizes when an NFS mount point
  mounts or unmounts, fixing these issues. (BZ#675058, BZ#706095, BZ#694767)

  * When a device name was longer than 13 characters, the iostat utility
  printed a redundant new line character, making its output less readable.
  This bug has been fixed and now, no extra characters are printed if a long
  device name occurs in iostat output. (BZ#604637)

 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"sysstat", rpm:"sysstat~7.0.2~11.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sysstat-debuginfo", rpm:"sysstat-debuginfo~7.0.2~11.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
