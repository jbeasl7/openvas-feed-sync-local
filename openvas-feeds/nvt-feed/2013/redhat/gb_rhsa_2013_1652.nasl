# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871071");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-11-21 10:43:37 +0530 (Thu, 21 Nov 2013)");
  script_cve_id("CVE-2013-0221", "CVE-2013-0222", "CVE-2013-0223");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for coreutils RHSA-2013:1652-02");


  script_tag(name:"affected", value:"coreutils on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"The coreutils package contains the core GNU utilities. It is a combination
of the old GNU fileutils, sh-utils, and textutils packages.

It was discovered that the sort, uniq, and join utilities did not properly
restrict the use of the alloca() function. An attacker could use this flaw
to crash those utilities by providing long input strings. (CVE-2013-0221,
CVE-2013-0222, CVE-2013-0223)

These updated coreutils packages include numerous bug fixes and two
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.5 Technical
Notes, linked to in the References, for information on the most significant
of these changes.

All coreutils users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2013:1652-02");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-November/msg00031.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'coreutils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"coreutils", rpm:"coreutils~8.4~31.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"coreutils-debuginfo", rpm:"coreutils-debuginfo~8.4~31.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"coreutils-libs", rpm:"coreutils-libs~8.4~31.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
