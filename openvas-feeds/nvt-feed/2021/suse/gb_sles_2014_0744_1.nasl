# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0744.1");
  script_cve_id("CVE-2013-1940", "CVE-2013-4396", "CVE-2013-6424");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0744-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0744-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140744-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server' package(s) announced via the SUSE-SU-2014:0744-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a SLES 11 SP1 LTSS rollup update for the X.Org Server package.

The following security issues have been fixed:

 * CVE-2013-6424: Integer underflow in the xTrapezoidValid macro in
 render/picture.h in X.Org allowed context-dependent attackers to
 cause a denial of service (crash) via a negative bottom value.
 * CVE-2013-4396: Use-after-free vulnerability in the doImageText
 function in dix/dixfonts.c in the xorg-server module before 1.14.4
 in X.Org X11 allowed remote authenticated users to cause a denial of
 service (daemon crash) or possibly execute arbitrary code via a
 crafted ImageText request that triggers memory-allocation failure.
 * CVE-2013-1940: X.Org X server did not properly restrict access to
 input events when adding a new hot-plug device, which might have
 allowed physically proximate attackers to obtain sensitive
 information, as demonstrated by reading passwords from a tty.

The following non-security issues have been fixed:

 * rfbAuthReenable is accessing rfbClient structure that was in most
 cases already freed. It actually needs only ScreenPtr, so pass it
 directly. (bnc#816813)
 * Memory leaks in ARGB cursor handling. (bnc#813178, bnc#813683)

Security Issues:

 * CVE-2013-1940
 * CVE-2013-4396
 * CVE-2013-6424");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on SUSE Linux Enterprise Server 11-SP1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~7.4~27.40.70.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~7.4~27.40.70.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~7.4~27.40.70.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
