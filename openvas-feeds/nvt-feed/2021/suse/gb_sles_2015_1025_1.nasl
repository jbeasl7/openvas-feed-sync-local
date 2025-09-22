# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1025.1");
  script_cve_id("CVE-2013-4396", "CVE-2013-6424", "CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8094", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102", "CVE-2015-0255", "CVE-2015-3418");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-15 15:12:59 +0000 (Thu, 15 Dec 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1025-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1025-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151025-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/816813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/843652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/874903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/878433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/878446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/879019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/886213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907268");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928520");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-June/001430.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server' package(s) announced via the SUSE-SU-2015:1025-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This collective update for xorg-x11-server provides the following fixes:

 * Fix a segmentation fault that can occur when X11 packets are
 forwarded between a client and a server with different endianess.
 (bnc#874903)
 * Free software cursor backing pixmap when transition between screens.
 This fixes a crash in multi screen support when an assert gets hit.
 (bnc#880835)
 * Ignore numlock in Xvnc. Following keys from VNC client will be
 already modulated by numlock on client side. (bnc#878446)
 * Fix crash when Xinerama gets disabled after RanR12 is initialized.
 (bnc#878433)
 * Prevent crash at the end of 2nd server generation when number of
 privates differ between 1st and 2nd. (bnc#883598)
 * Move Xinerama disable when only one screen is present to main loop.
 (bnc#883598)
 * Improve Xinerama command line option handling. (bnc#883598)
 * Work around a possible crash when object belongs to a client that no
 longer exists. (bnc#883516)
 * Try to make keyboard bell ring on all devices attached to master
 keyboard. (bnc#879019)
 * Implement DeleteInputDeviceRequest in Xvnc to avoid server crash when
 the Xserver restarts after a server reset. (bnc#880745).");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-Xvnc", rpm:"xorg-x11-Xvnc~7.4~27.97.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~7.4~27.97.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~7.4~27.97.1", rls:"SLES11.0SP3"))) {
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
