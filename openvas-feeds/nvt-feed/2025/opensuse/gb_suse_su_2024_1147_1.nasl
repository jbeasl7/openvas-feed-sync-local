# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.1147.1");
  script_cve_id("CVE-2023-5388", "CVE-2024-0743", "CVE-2024-2605", "CVE-2024-2607", "CVE-2024-2608", "CVE-2024-2610", "CVE-2024-2611", "CVE-2024-2612", "CVE-2024-2614", "CVE-2024-2616");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-25 14:47:29 +0000 (Tue, 25 Feb 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1147-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1147-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241147-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221327");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/034875.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2024:1147-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

- Mozilla Thunderbird 115.9 (bsc#1221327)
- CVE-2024-0743: Crash in NSS TLS method
- CVE-2024-2605: Windows Error Reporter could be used as a Sandbox escape vector
- CVE-2024-2607: JIT code failed to save return registers on Armv7-A
- CVE-2024-2608: Integer overflow could have led to out of bounds write
- CVE-2024-2616: Improve handling of out-of-memory conditions in ICU
- CVE-2023-5388: NSS susceptible to timing attack against RSA decryption
- CVE-2024-2610: Improper handling of html and body tags enabled CSP nonce leakage
- CVE-2024-2611: Clickjacking vulnerability could have led to a user accidentally granting permissions
- CVE-2024-2612: Self referencing object could have potentially led to a use- after-free
- CVE-2024-2614: Memory safety bugs fixed in Firefox 124, Firefox ESR 115.9, and Thunderbird 115.9");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~115.9.0~150200.8.154.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~115.9.0~150200.8.154.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~115.9.0~150200.8.154.1", rls:"openSUSELeap15.5"))) {
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
