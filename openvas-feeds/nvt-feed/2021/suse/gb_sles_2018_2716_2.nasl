# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2716.2");
  script_cve_id("CVE-2017-9269", "CVE-2018-7685");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-26 17:17:54 +0000 (Mon, 26 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2716-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2716-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182716-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102429");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004713.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libzypp, zypper' package(s) announced via the SUSE-SU-2018:2716-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libzypp, zypper provides the following fixes:

Update libzypp to version 16.17.20

Security issues fixed:

- PackageProvider: Validate delta rpms before caching (bsc#1091624,
 bsc#1088705, CVE-2018-7685)
- PackageProvider: Validate downloaded rpm package signatures before
 caching (bsc#1091624, bsc#1088705, CVE-2018-7685)

Other bugs fixed:

- lsof: use '-K i' if lsof supports it (bsc#1099847, bsc#1036304)
- Handle http error 502 Bad Gateway in curl backend (bsc#1070851)
- RepoManager: Explicitly request repo2solv to generate application
 pseudo packages.
- libzypp-devel should not require cmake (bsc#1101349)
- HardLocksFile: Prevent against empty commit without Target having
 been been loaded (bsc#1096803)
- Avoid zombie tar processes (bsc#1076192)

Update to zypper to version 1.13.45

Security issue fixed:
- Improve signature check callback messages
 (bsc#1045735, CVE-2017-9269)
- add/modify repo: Add options to tune the GPG check settings
 (bsc#1045735, CVE-2017-9269)

Other bugs fixed:

- XML <install-summary> attribute `packages-to-change` added (bsc#1102429)
- man: Strengthen that `--config FILE' affects zypper.conf,
 not zypp.conf (bsc#1100028)
- Prevent nested calls to exit() if aborted by a signal (bsc#1092413)
- ansi.h: Prevent ESC sequence strings from going out of scope (bsc#1092413)
- Fix: zypper bash completion expands non-existing options (bsc#1049825)
- do not recommend cron (bsc#1079334)
- Improve signature check callback messages (bsc#1045735)
- add/modify repo: Add options to tune the GPG check settings (bsc#1045735)");

  script_tag(name:"affected", value:"'libzypp, zypper' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~16.17.20~27.52.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper", rpm:"zypper~1.13.45~18.33.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-log", rpm:"zypper-log~1.13.45~18.33.1", rls:"SLES12.0SP2"))) {
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
