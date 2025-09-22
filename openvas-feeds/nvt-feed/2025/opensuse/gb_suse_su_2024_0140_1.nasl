# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0140.1");
  script_cve_id("CVE-2023-1667", "CVE-2023-2283", "CVE-2023-48795", "CVE-2023-6004", "CVE-2023-6918");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-06 14:54:27 +0000 (Tue, 06 Jun 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0140-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0140-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240140-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218209");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-January/017678.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh' package(s) announced via the SUSE-SU-2024:0140-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2023-6004: Fixed command injection using proxycommand (bsc#1218209)
 - CVE-2023-48795: Fixed potential downgrade attack using strict kex (bsc#1218126)
 - CVE-2023-6918: Fixed missing checks for return values of MD functions (bsc#1218186)
 - CVE-2023-1667: Fixed NULL dereference during rekeying with algorithm guessing (bsc#1211188)
 - CVE-2023-2283: Fixed possible authorization bypass in pki_verify_data_signature under low-memory conditions (bsc#1211190)

Other fixes:

- Update to version 0.9.8
 - Allow @ in usernames when parsing from URI composes

- Update to version 0.9.7
 - Fix several memory leaks in GSSAPI handling code");

  script_tag(name:"affected", value:"'libssh' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"libssh-config", rpm:"libssh-config~0.9.8~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh-devel", rpm:"libssh-devel~0.9.8~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh4", rpm:"libssh4~0.9.8~150400.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh4-32bit", rpm:"libssh4-32bit~0.9.8~150400.3.3.1", rls:"openSUSELeap15.5"))) {
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
