# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02546.1");
  script_cve_id("CVE-2025-6424", "CVE-2025-6425", "CVE-2025-6426", "CVE-2025-6427", "CVE-2025-6429", "CVE-2025-6430", "CVE-2025-6432", "CVE-2025-6433", "CVE-2025-6434", "CVE-2025-6435", "CVE-2025-6436", "CVE-2025-8027", "CVE-2025-8028", "CVE-2025-8029", "CVE-2025-8030", "CVE-2025-8031", "CVE-2025-8032", "CVE-2025-8033", "CVE-2025-8034", "CVE-2025-8035", "CVE-2025-8036", "CVE-2025-8037", "CVE-2025-8038", "CVE-2025-8039", "CVE-2025-8040");
  script_tag(name:"creation_date", value:"2025-07-31 04:20:33 +0000 (Thu, 31 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02546-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02546-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502546-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246664");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040955.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2025:02546-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

Update to Mozilla Thunderbird 140.1 (MFSA 2025-63) (bsc#1246664):

- CVE-2025-8027: JavaScript engine only wrote partial return value to stack (bmo#1968423)
- CVE-2025-8028: Large branch table could lead to truncated instruction (bmo#1971581)
- CVE-2025-8029: javascript: URLs executed on object and embed tags (bmo#1928021)
- CVE-2025-8036: DNS rebinding circumvents CORS (bmo#1960834)
- CVE-2025-8037: Nameless cookies shadow secure cookies (bmo#1964767)
- CVE-2025-8030: Potential user-assisted code execution in 'Copy as cURL' command (bmo#1968414)
- CVE-2025-8031: Incorrect URL stripping in CSP reports (bmo#1971719)
- CVE-2025-8032: XSLT documents could bypass CSP (bmo#1974407)
- CVE-2025-8038: CSP frame-src was not correctly enforced for paths (bmo#1808979)
- CVE-2025-8039: Search terms persisted in URL bar (bmo#1970997)
- CVE-2025-8033: Incorrect JavaScript state machine for generators (bmo#1973990)
- CVE-2025-8034: Memory safety bugs fixed in Firefox ESR 115.26, Firefox ESR 128.13, Thunderbird ESR 128.13, Firefox ESR 140.1, Thunderbird ESR 140.1, Firefox 141 and Thunderbird 141 (bmo#1970422, bmo#1970422, bmo#1970422, bmo#1970422)
- CVE-2025-8040: Memory safety bugs fixed in Firefox ESR 140.1, Thunderbird ESR 140.1, Firefox 141 and Thunderbird 141 (bmo#1975058, bmo#1975058, bmo#1975998, bmo#1975998)
- CVE-2025-8035: Memory safety bugs fixed in Firefox ESR 128.13, Thunderbird ESR 128.13, Firefox ESR 140.1, Thunderbird ESR 140.1, Firefox 141 and Thunderbird 141 (bmo#1975961, bmo#1975961, bmo#1975961)

Update to Mozilla Thunderbird 140.0.1 (MFSA 2025-54) (bsc#1244670):

- CVE-2025-6424: Use-after-free in FontFaceSet (bmo#1966423)
- CVE-2025-6425: The WebCompat WebExtension shipped exposed a persistent UUID (bmo#1717672)
- CVE-2025-6426: No warning when opening executable terminal files on macOS (bmo#1964385)
- CVE-2025-6427: connect-src Content Security Policy restriction could be bypassed (bmo#1966927)
- CVE-2025-6429: Incorrect parsing of URLs could have allowed embedding of youtube.com (bmo#1970658)
- CVE-2025-6430: Content-Disposition header ignored when a file is included in an embed or object tag (bmo#1971140)
- CVE-2025-6432: DNS Requests leaked outside of a configured SOCKS proxy (bmo#1943804)
- CVE-2025-6433: WebAuthn would allow a user to sign a challenge on a webpage with an invalid TLS certificate (bmo#1954033)
- CVE-2025-6434: HTTPS-Only exception screen lacked anti-clickjacking delay (bmo#1955182)
- CVE-2025-6435: Save as in Devtools could download files without sanitizing the extension (bmo#1950056, bmo#1961777)
- CVE-2025-6436: Memory safety bugs fixed in Firefox 140 and Thunderbird 140 (bmo#1941377, bmo#1960948, bmo#1966187, bmo#1966505, bmo#1970764)");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~140.1.0~150200.8.230.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~140.1.0~150200.8.230.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~140.1.0~150200.8.230.1", rls:"openSUSELeap15.6"))) {
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
