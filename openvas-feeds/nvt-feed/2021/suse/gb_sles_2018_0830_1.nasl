# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0830.1");
  script_cve_id("CVE-2016-9941", "CVE-2016-9942", "CVE-2018-7225");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-19 15:20:21 +0000 (Mon, 19 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0830-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0830-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180830-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081493");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-March/003847.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibVNCServer' package(s) announced via the SUSE-SU-2018:0830-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LibVNCServer was updated to fix two security issues.

These security issues were fixed:

- CVE-2018-7225: Missing input sanitization inside rfbserver.c rfbProcessClientNormalMessage() (bsc#1081493).
- CVE-2016-9942: Heap-based buffer overflow in ultra.c allowed remote servers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted FramebufferUpdate message with the Ultra type tile, such that the LZO payload decompressed length exceeds what is specified by the tile dimensions (bsc#1017712).
- CVE-2016-9941: Heap-based buffer overflow in rfbproto.c allowed remote servers to cause a denial of service (application crash) or possibly execute arbitrary code via a crafted FramebufferUpdate message containing a subrectangle outside of the client drawing area (bsc#1017711).");

  script_tag(name:"affected", value:"'LibVNCServer' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libvncclient0", rpm:"libvncclient0~0.9.9~17.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver0", rpm:"libvncserver0~0.9.9~17.5.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libvncclient0", rpm:"libvncclient0~0.9.9~17.5.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver0", rpm:"libvncserver0~0.9.9~17.5.1", rls:"SLES12.0SP3"))) {
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
