# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-June/msg00037.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870776");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-22 10:26:31 +0530 (Fri, 22 Jun 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2012-2664");
  script_xref(name:"RHSA", value:"2012:0958-04");
  script_name("RedHat Update for sos RHSA-2012:0958-04");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sos'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"sos on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The sos package contains a set of tools that gather information from system
  hardware, logs and configuration files. The information can then be used
  for diagnostic purposes and debugging.

  The sosreport utility collected the Kickstart configuration file
  ('/root/anaconda-ks.cfg'), but did not remove the root user's password from
  it before adding the file to the resulting archive of debugging
  information. An attacker able to access the archive could possibly use this
  flaw to obtain the root user's password. '/root/anaconda-ks.cfg' usually
  only contains a hash of the password, not the plain text password.
  (CVE-2012-2664)

  Note: This issue affected all installations, not only systems installed via
  Kickstart. A '/root/anaconda-ks.cfg' file is created by all installation
  types.

  This updated sos package also includes numerous bug fixes and enhancements.
  Space precludes documenting all of these changes in this advisory. Users
  are directed to the Red Hat Enterprise Linux 6.3 Technical Notes for
  information on the most significant of these changes.

  All users of sos are advised to upgrade to this updated package, which
  contains backported patches to correct these issues and add these
  enhancements.");
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

  if ((res = isrpmvuln(pkg:"sos", rpm:"sos~2.2~29.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
