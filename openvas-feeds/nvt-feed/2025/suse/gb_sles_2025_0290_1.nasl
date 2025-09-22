# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0290.1");
  script_cve_id("CVE-2020-6923");
  script_tag(name:"creation_date", value:"2025-01-30 04:33:12 +0000 (Thu, 30 Jan 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0290-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0290-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250290-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234745");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020238.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hplip' package(s) announced via the SUSE-SU-2025:0290-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hplip fixes the following issues:

This update for hplip fixes the following security issues:

- CVE-2020-6923: Fixed a memory buffer overflow in the HP Linux Imaging and Printing (HPLIP). (bsc#1234745)

This update for hplip fixes the following issues:

Update to hplip 3.24.4 (jsc#PED-5846)

- Added support for new printers:
 * Digital Sender Flow 8500 fn2
 * HP Color LaserJet Managed FlowMFP E786z
 * HP Color LaserJet E85055dn
 * HP Color LaserJet Enterprise 5700
 * HP Color LaserJet Enterprise 5700dn
 * HP Color LaserJet Enterprise 6700
 * HP Color LaserJet Enterprise 6700dn
 * HP Color LaserJet Enterprise 6701
 * HP Color LaserJet Enterprise 6701dn
 * HP Color LaserJet Enterprise Flow MFP 5800zf
 * HP Color LaserJet Enterprise Flow MFP 6800zf
 * HP Color LaserJet Enterprise Flow MFP 6800zfsw
 * HP Color LaserJet Enterprise Flow MFP 6800zfw+
 * HP Color LaserJet Enterprise Flow MFP 6801zfw+
 * HP Color LaserJet Enterprise Flow MFP M578c
 * HP Color LaserJet Enterprise Flow MFP M578z
 * HP Color LaserJet Enterprise Flow MFP X57945z
 * HP Color LaserJet Enterprise Flow MFP X57945zs
 * HP Color LaserJet Enterprise Flow MFP X58045z
 * HP Color LaserJet Enterprise Flow MFP X58045zs
 * HP Color LaserJet Enterprise Flow MFP X67755z+
 * HP Color LaserJet Enterprise Flow MFP X67755zs
 * HP Color LaserJet Enterprise Flow MFP X67765z+
 * HP Color LaserJet Enterprise Flow MFP X67765zs
 * HP Color LaserJet Enterprise Flow MFP X677z
 * HP Color LaserJet Enterprise Flow MFP X677z+
 * HP Color LaserJet Enterprise Flow MFP X677zs
 * HP Color LaserJet Enterprise M455dn
 * HP Color LaserJet Enterprise M554dn
 * HP Color LaserJet Enterprise M555dn
 * HP Color LaserJet Enterprise M555x
 * HP Color LaserJet Enterprise M751dn
 * HP Color LaserJet Enterprise M751n
 * HP Color LaserJet Enterprise MFP 5800
 * HP Color LaserJet Enterprise MFP 5800dn
 * HP Color LaserJet Enterprise MFP 5800f
 * HP Color LaserJet Enterprise MFP 6800
 * HP Color LaserJet Enterprise MFP 6800dn
 * HP Color LaserJet Enterprise MFP 6801
 * HP Color LaserJet Enterprise MFP 6801 zfsw
 * HP Color LaserJet Enterprise MFP M480f
 * HP Color LaserJet Enterprise MFP M578dn
 * HP Color LaserJet Enterprise MFP M578f
 * HP Color LaserJet Enterprise MFP X57945
 * HP Color LaserJet Enterprise MFP X57945dn
 * HP Color LaserJet Enterprise MFP X58045
 * HP Color LaserJet Enterprise MFP X58045dn
 * HP Color LaserJet Enterprise MFP X677
 * HP Color LaserJet Enterprise MFP X677 55 to 65ppm License
 * HP Color LaserJet Enterprise MFP X677 65ppm
 * HP Color LaserJet Enterprise MFP X67755dn
 * HP Color LaserJet Enterprise MFP X67765dn
 * HP Color LaserJet Enterprise MFP X677dn
 * HP Color LaserJet Enterprise MFP X677s
 * HP Color LaserJet Enterprise X55745
 * HP Color LaserJet Enterprise X55745dn
 * HP Color LaserJet Enterprise X654
 * HP Color LaserJet Enterprise X654 55 to 65ppm License
 * HP Color LaserJet Enterprise ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'hplip' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"hplip", rpm:"hplip~3.24.4~3.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-devel", rpm:"hplip-devel~3.24.4~3.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-hpijs", rpm:"hplip-hpijs~3.24.4~3.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-sane", rpm:"hplip-sane~3.24.4~3.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-udev-rules", rpm:"hplip-udev-rules~3.24.4~3.5.1", rls:"SLES12.0SP5"))) {
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
