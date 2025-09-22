# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018723.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881136");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:20:29 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-2664");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_xref(name:"CESA", value:"2012:0958");
  script_name("CentOS Update for sos CESA-2012:0958 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sos'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"sos on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
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
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"sos", rpm:"sos~2.2~29.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
