# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2344.1");
  script_cve_id("CVE-2017-7436");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-21 15:13:10 +0000 (Wed, 21 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2344-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2344-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172344-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055920");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-September/003183.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libzypp, zypper' package(s) announced via the SUSE-SU-2017:2344-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Software Update Stack was updated to receive fixes and enhancements.

libzypp:

- Adapt to work with GnuPG 2.1.23. (bsc#1054088)
- Support signing with subkeys. (bsc#1008325)
- Enhance sort order for media.1/products. (bsc#1054671)

zypper:

- Also show a gpg key's subkeys. (bsc#1008325)
- Improve signature check callback messages. (bsc#1045735)
- Add options to tune the GPG check settings. (bsc#1045735)
- Adapt download callback to report and handle unsigned packages. (bsc#1038984, CVE-2017-7436)
- Report missing/optional files as 'not found' rather than 'error'. (bsc#1047785)");

  script_tag(name:"affected", value:"'libzypp, zypper' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~16.15.6~2.8.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper", rpm:"zypper~1.13.32~21.3.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-log", rpm:"zypper-log~1.13.32~21.3.2", rls:"SLES12.0SP3"))) {
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
