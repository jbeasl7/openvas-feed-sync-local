# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.989897981019710041007");
  script_cve_id("CVE-2025-0638");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-bbabead4d7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-bbabead4d7");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-bbabead4d7");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2339700");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/routinator-ui/releases/tag/v0.4.3");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/routinator/pull/980");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/routinator/pull/982");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/routinator/pull/987");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/routinator/pull/990");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/routinator/pull/992");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/routinator/pull/994");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/routinator/pull/996");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/routinator/pull/997");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/routinator/pull/999");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/rpki-rs/pull/319");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/rpki-rs/pull/320");
  script_xref(name:"URL", value:"https://github.com/sleinen");
  script_xref(name:"URL", value:"https://www.nlnetlabs.nl/downloads/routinator/CVE-2025-0638.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-routinator' package(s) announced via the FEDORA-2025-bbabead4d7 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"## New

* ASPA support is now always compiled in and available if `enable-aspa` is set. The `aspa` Cargo feature has been removed. ([#990])
* If merging mutliple ASPA objects for a single customer ASN results in more than 16,380 provider ASNs, the ASPA is dropped. (Note that ASPA objects with more than 16,380 provider ASNs are already rejected during parsing.) ([#996])
* New `archive-stats` command that shows some statistics of an RRDP archive. ([#982])
* Re-enabled the use of GZIP compression in HTTP request sent by the RRDP collector. Measures to deal with exploding data have been implemented in [rpki-rs#319]. ([#997])

## Bug fixes

* Fixed an issue with checking the file names in manifests that let to a crash when non-ASCII characters are used. ([rpki-rs#320], reported by Haya Schulmann and Niklas Vogel of Goethe University Frankfurt/ATHENE Center and assigned [CVE-2025-0638])
* The validation HTTP endpoints now accept prefixes with non-zero host bits. ([#987])
* Removed duplicate `rtr_client_reset_queries` in HTTP metrics. ([#992] by [@sleinen])
* Improved disk space consumption of the new RRDP archives by re-using empty space when updating an object and padding all objects to a multiple of 256 bytes. ([#982])

[#980]: [link moved to references]
[#982]: [link moved to references]
[#987]: [link moved to references]
[#990]: [link moved to references]
[#992]: [link moved to references]
[#994]: [link moved to references]
[#996]: [link moved to references]
[#997]: [link moved to references]
[#999]: [link moved to references]
[@sleinen]: [link moved to references]
[rpki-rs#319]: [link moved to references]
[rpki-rs#320]: [link moved to references]
[ui-0.4.3]: [link moved to references]
[CVE-2025-0638]: [link moved to references]");

  script_tag(name:"affected", value:"'rust-routinator' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"routinator", rpm:"routinator~0.14.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"routinator-debuginfo", rpm:"routinator-debuginfo~0.14.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+arbitrary-devel", rpm:"rust-routinator+arbitrary-devel~0.14.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+default-devel", rpm:"rust-routinator+default-devel~0.14.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+native-tls-devel", rpm:"rust-routinator+native-tls-devel~0.14.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+rta-devel", rpm:"rust-routinator+rta-devel~0.14.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+socks-devel", rpm:"rust-routinator+socks-devel~0.14.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+ui-devel", rpm:"rust-routinator+ui-devel~0.14.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator", rpm:"rust-routinator~0.14.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator-debugsource", rpm:"rust-routinator-debugsource~0.14.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator-devel", rpm:"rust-routinator-devel~0.14.1~2.fc41", rls:"FC41"))) {
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
