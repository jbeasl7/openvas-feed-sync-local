# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871616");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-05-11 05:23:30 +0200 (Wed, 11 May 2016)");
  script_cve_id("CVE-2014-3538", "CVE-2014-3587", "CVE-2014-3710", "CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9620", "CVE-2014-9653", "CVE-2012-1571");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for file RHSA-2016:0760-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'file'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The file command is used to identify a particular file according to the
type of data the file contains. It can identify many different file types,
including Executable and Linkable Format (ELF) binary files, system
libraries, RPM packages, and different graphics formats.

Security Fix(es):

  * Multiple flaws were found in the file regular expression rules for
detecting various files. A remote attacker could use these flaws to cause
file to consume an excessive amount of CPU. (CVE-2014-3538)

  * A denial of service flaw was found in the way file parsed certain
Composite Document Format (CDF) files. A remote attacker could use this
flaw to crash file via a specially crafted CDF file. (CVE-2014-3587)

  * Multiple flaws were found in the way file parsed Executable and Linkable
Format (ELF) files. A remote attacker could use these flaws to cause file
to crash, disclose portions of its memory, or consume an excessive amount
of system resources. (CVE-2014-3710, CVE-2014-8116, CVE-2014-8117,
CVE-2014-9620, CVE-2014-9653)

Red Hat would like to thank Thomas Jarosch (Intra2net AG) for reporting
CVE-2014-8116 and CVE-2014-8117. The CVE-2014-3538 issue was discovered by
Jan Kalua (Red Hat Web Stack Team) and the CVE-2014-3710 issue was
discovered by Francisco Alonso (Red Hat Product Security).

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.8 Release Notes and Red Hat Enterprise Linux 6.8
Technical Notes linked from the References section.");
  script_tag(name:"affected", value:"file on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:0760-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-May/msg00020.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"file", rpm:"file~5.04~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"file-debuginfo", rpm:"file-debuginfo~5.04~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"file-devel", rpm:"file-devel~5.04~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"file-libs", rpm:"file-libs~5.04~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-magic", rpm:"python-magic~5.04~30.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}