# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.198308999689");
  script_cve_id("CVE-2024-45305", "CVE-2024-45405");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-1b3089c689)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-1b3089c689");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-1b3089c689");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299560");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299565");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299568");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299569");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299584");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299588");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299589");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300466");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2301550");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303943");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307375");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307376");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307377");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307378");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307379");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307380");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307381");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307382");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307383");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307384");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307385");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307386");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307387");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307388");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307389");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307390");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307391");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307392");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307393");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307394");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307395");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307396");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307397");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307398");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307399");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307400");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307401");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307402");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307403");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307404");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307405");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307406");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307407");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307408");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307409");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2307451");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2309351");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2309352");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310363");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310416");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310417");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'helix, rust-cargo, rust-cargo-deny, rust-dua-cli, rust-gix, rust-gix-actor, rust-gix-archive, rust-gix-attributes, rust-gix-command, rust-gix-commitgraph, rust-gix-config, rust-gix-config-value, rust-gix-credentials, rust-gix-date, rust-gix-diff, rust-gix-dir, rust-gix-discover, rust-gix-features, rust-gix-filter, rust-gix-fs, rust-gix-glob, rust-gix-ignore, rust-gix-index, rust-gix-mailmap, rust-gix-negotiate, rust-gix-object, rust-gix-odb, rust-gix-pack, rust-gix-packetline, rust-gix-packetline-blocking, rust-gix-path, rust-gix-pathspec, rust-gix-prompt, rust-gix-protocol, rust-gix-ref, rust-gix-refspec, rust-gix-revision, rust-gix-revwalk, rust-gix-sec, rust-gix-status, rust-gix-submodule, rust-gix-tempfile, rust-gix-trace, rust-gix-transport, rust-gix-traverse, rust-gix-url, rust-gix-validate, rust-gix-worktree, rust-gix-worktree-state, rust-gix-worktree-stream, rust-onefetch, rust-prodash, rust-rustsec, rust-tame-index, rust-vergen, stgit' package(s) announced via the FEDORA-2024-1b3089c689 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update `gix` to version 0.66");

  script_tag(name:"affected", value:"'helix, rust-cargo, rust-cargo-deny, rust-dua-cli, rust-gix, rust-gix-actor, rust-gix-archive, rust-gix-attributes, rust-gix-command, rust-gix-commitgraph, rust-gix-config, rust-gix-config-value, rust-gix-credentials, rust-gix-date, rust-gix-diff, rust-gix-dir, rust-gix-discover, rust-gix-features, rust-gix-filter, rust-gix-fs, rust-gix-glob, rust-gix-ignore, rust-gix-index, rust-gix-mailmap, rust-gix-negotiate, rust-gix-object, rust-gix-odb, rust-gix-pack, rust-gix-packetline, rust-gix-packetline-blocking, rust-gix-path, rust-gix-pathspec, rust-gix-prompt, rust-gix-protocol, rust-gix-ref, rust-gix-refspec, rust-gix-revision, rust-gix-revwalk, rust-gix-sec, rust-gix-status, rust-gix-submodule, rust-gix-tempfile, rust-gix-trace, rust-gix-transport, rust-gix-traverse, rust-gix-url, rust-gix-validate, rust-gix-worktree, rust-gix-worktree-state, rust-gix-worktree-stream, rust-onefetch, rust-prodash, rust-rustsec, rust-tame-index, rust-vergen, stgit' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"cargo-deny", rpm:"cargo-deny~0.14.24~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-deny-debuginfo", rpm:"cargo-deny-debuginfo~0.14.24~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dua-cli", rpm:"dua-cli~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dua-cli-debuginfo", rpm:"dua-cli-debuginfo~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helix", rpm:"helix~24.07~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helix-debuginfo", rpm:"helix-debuginfo~24.07~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helix-debugsource", rpm:"helix-debugsource~24.07~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"onefetch", rpm:"onefetch~2.21.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"onefetch-debuginfo", rpm:"onefetch-debuginfo~2.21.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo+default-devel", rpm:"rust-cargo+default-devel~0.79.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo+openssl-devel", rpm:"rust-cargo+openssl-devel~0.79.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo", rpm:"rust-cargo~0.79.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny+default-devel", rpm:"rust-cargo-deny+default-devel~0.14.24~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny+native-certs-devel", rpm:"rust-cargo-deny+native-certs-devel~0.14.24~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny", rpm:"rust-cargo-deny~0.14.24~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny-debugsource", rpm:"rust-cargo-deny-debugsource~0.14.24~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny-devel", rpm:"rust-cargo-deny-devel~0.14.24~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-devel", rpm:"rust-cargo-devel~0.79.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+crosstermion-devel", rpm:"rust-dua-cli+crosstermion-devel~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+default-devel", rpm:"rust-dua-cli+default-devel~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+open-devel", rpm:"rust-dua-cli+open-devel~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+trash-devel", rpm:"rust-dua-cli+trash-devel~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+trash-move-devel", rpm:"rust-dua-cli+trash-move-devel~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+tui-crossplatform-devel", rpm:"rust-dua-cli+tui-crossplatform-devel~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+tui-devel", rpm:"rust-dua-cli+tui-devel~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+tui-react-devel", rpm:"rust-dua-cli+tui-react-devel~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+unicode-segmentation-devel", rpm:"rust-dua-cli+unicode-segmentation-devel~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+unicode-width-devel", rpm:"rust-dua-cli+unicode-width-devel~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli", rpm:"rust-dua-cli~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli-debugsource", rpm:"rust-dua-cli-debugsource~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli-devel", rpm:"rust-dua-cli-devel~2.29.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+async-network-client-async-std-devel", rpm:"rust-gix+async-network-client-async-std-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+async-network-client-devel", rpm:"rust-gix+async-network-client-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+async-std-devel", rpm:"rust-gix+async-std-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+attributes-devel", rpm:"rust-gix+attributes-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+basic-devel", rpm:"rust-gix+basic-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+blob-diff-devel", rpm:"rust-gix+blob-diff-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+blocking-http-transport-curl-devel", rpm:"rust-gix+blocking-http-transport-curl-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+blocking-http-transport-reqwest-devel", rpm:"rust-gix+blocking-http-transport-reqwest-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+blocking-http-transport-reqwest-native-tls-devel", rpm:"rust-gix+blocking-http-transport-reqwest-native-tls-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+blocking-http-transport-reqwest-rust-tls-devel", rpm:"rust-gix+blocking-http-transport-reqwest-rust-tls-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+blocking-http-transport-reqwest-rust-tls-trust-dns-devel", rpm:"rust-gix+blocking-http-transport-reqwest-rust-tls-trust-dns-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+blocking-network-client-devel", rpm:"rust-gix+blocking-network-client-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+cache-efficiency-debug-devel", rpm:"rust-gix+cache-efficiency-debug-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+comfort-devel", rpm:"rust-gix+comfort-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+command-devel", rpm:"rust-gix+command-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+credentials-devel", rpm:"rust-gix+credentials-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+default-devel", rpm:"rust-gix+default-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+dirwalk-devel", rpm:"rust-gix+dirwalk-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+document-features-devel", rpm:"rust-gix+document-features-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+excludes-devel", rpm:"rust-gix+excludes-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+extras-devel", rpm:"rust-gix+extras-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+fast-sha1-devel", rpm:"rust-gix+fast-sha1-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+gix-archive-devel", rpm:"rust-gix+gix-archive-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+gix-protocol-devel", rpm:"rust-gix+gix-protocol-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+gix-status-devel", rpm:"rust-gix+gix-status-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+gix-transport-devel", rpm:"rust-gix+gix-transport-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+gix-worktree-stream-devel", rpm:"rust-gix+gix-worktree-stream-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+hp-tempfile-registry-devel", rpm:"rust-gix+hp-tempfile-registry-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+index-devel", rpm:"rust-gix+index-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+interrupt-devel", rpm:"rust-gix+interrupt-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+mailmap-devel", rpm:"rust-gix+mailmap-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+max-control-devel", rpm:"rust-gix+max-control-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+max-performance-devel", rpm:"rust-gix+max-performance-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+max-performance-safe-devel", rpm:"rust-gix+max-performance-safe-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+pack-cache-lru-dynamic-devel", rpm:"rust-gix+pack-cache-lru-dynamic-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+pack-cache-lru-static-devel", rpm:"rust-gix+pack-cache-lru-static-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+parallel-devel", rpm:"rust-gix+parallel-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+parallel-walkdir-devel", rpm:"rust-gix+parallel-walkdir-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+prodash-devel", rpm:"rust-gix+prodash-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+progress-tree-devel", rpm:"rust-gix+progress-tree-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+regex-devel", rpm:"rust-gix+regex-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+revision-devel", rpm:"rust-gix+revision-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+revparse-regex-devel", rpm:"rust-gix+revparse-regex-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+serde-devel", rpm:"rust-gix+serde-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+status-devel", rpm:"rust-gix+status-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+tracing-detail-devel", rpm:"rust-gix+tracing-detail-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+tracing-devel", rpm:"rust-gix+tracing-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+verbose-object-parsing-errors-devel", rpm:"rust-gix+verbose-object-parsing-errors-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+worktree-archive-devel", rpm:"rust-gix+worktree-archive-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+worktree-mutation-devel", rpm:"rust-gix+worktree-mutation-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+worktree-stream-devel", rpm:"rust-gix+worktree-stream-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+zlib-ng-devel", rpm:"rust-gix+zlib-ng-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix+zlib-stock-devel", rpm:"rust-gix+zlib-stock-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix", rpm:"rust-gix~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-actor+default-devel", rpm:"rust-gix-actor+default-devel~0.32.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-actor+document-features-devel", rpm:"rust-gix-actor+document-features-devel~0.32.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-actor+serde-devel", rpm:"rust-gix-actor+serde-devel~0.32.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-actor", rpm:"rust-gix-actor~0.32.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-actor-devel", rpm:"rust-gix-actor-devel~0.32.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-archive+default-devel", rpm:"rust-gix-archive+default-devel~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-archive+document-features-devel", rpm:"rust-gix-archive+document-features-devel~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-archive+tar-devel", rpm:"rust-gix-archive+tar-devel~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-archive+tar_gz-devel", rpm:"rust-gix-archive+tar_gz-devel~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-archive+zip-devel", rpm:"rust-gix-archive+zip-devel~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-archive", rpm:"rust-gix-archive~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-archive-devel", rpm:"rust-gix-archive-devel~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-attributes+default-devel", rpm:"rust-gix-attributes+default-devel~0.22.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-attributes+document-features-devel", rpm:"rust-gix-attributes+document-features-devel~0.22.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-attributes+serde-devel", rpm:"rust-gix-attributes+serde-devel~0.22.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-attributes", rpm:"rust-gix-attributes~0.22.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-attributes-devel", rpm:"rust-gix-attributes-devel~0.22.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-command+default-devel", rpm:"rust-gix-command+default-devel~0.3.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-command", rpm:"rust-gix-command~0.3.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-command-devel", rpm:"rust-gix-command-devel~0.3.9~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-commitgraph+default-devel", rpm:"rust-gix-commitgraph+default-devel~0.24.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-commitgraph+document-features-devel", rpm:"rust-gix-commitgraph+document-features-devel~0.24.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-commitgraph+serde-devel", rpm:"rust-gix-commitgraph+serde-devel~0.24.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-commitgraph", rpm:"rust-gix-commitgraph~0.24.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-commitgraph-devel", rpm:"rust-gix-commitgraph-devel~0.24.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-config+default-devel", rpm:"rust-gix-config+default-devel~0.40.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-config+document-features-devel", rpm:"rust-gix-config+document-features-devel~0.40.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-config+serde-devel", rpm:"rust-gix-config+serde-devel~0.40.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-config", rpm:"rust-gix-config~0.40.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-config-devel", rpm:"rust-gix-config-devel~0.40.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-config-value+default-devel", rpm:"rust-gix-config-value+default-devel~0.14.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-config-value+document-features-devel", rpm:"rust-gix-config-value+document-features-devel~0.14.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-config-value+serde-devel", rpm:"rust-gix-config-value+serde-devel~0.14.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-config-value", rpm:"rust-gix-config-value~0.14.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-config-value-devel", rpm:"rust-gix-config-value-devel~0.14.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-credentials+default-devel", rpm:"rust-gix-credentials+default-devel~0.24.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-credentials+document-features-devel", rpm:"rust-gix-credentials+document-features-devel~0.24.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-credentials+serde-devel", rpm:"rust-gix-credentials+serde-devel~0.24.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-credentials", rpm:"rust-gix-credentials~0.24.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-credentials-devel", rpm:"rust-gix-credentials-devel~0.24.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-date+default-devel", rpm:"rust-gix-date+default-devel~0.9.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-date+document-features-devel", rpm:"rust-gix-date+document-features-devel~0.9.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-date+serde-devel", rpm:"rust-gix-date+serde-devel~0.9.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-date", rpm:"rust-gix-date~0.9.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-date-devel", rpm:"rust-gix-date-devel~0.9.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-devel", rpm:"rust-gix-devel~0.66.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-diff+blob-devel", rpm:"rust-gix-diff+blob-devel~0.46.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-diff+default-devel", rpm:"rust-gix-diff+default-devel~0.46.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-diff+document-features-devel", rpm:"rust-gix-diff+document-features-devel~0.46.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-diff+serde-devel", rpm:"rust-gix-diff+serde-devel~0.46.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-diff", rpm:"rust-gix-diff~0.46.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-diff-devel", rpm:"rust-gix-diff-devel~0.46.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-dir+default-devel", rpm:"rust-gix-dir+default-devel~0.8.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-dir", rpm:"rust-gix-dir~0.8.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-dir-devel", rpm:"rust-gix-dir-devel~0.8.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-discover+default-devel", rpm:"rust-gix-discover+default-devel~0.35.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-discover", rpm:"rust-gix-discover~0.35.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-discover-devel", rpm:"rust-gix-discover-devel~0.35.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+cache-efficiency-debug-devel", rpm:"rust-gix-features+cache-efficiency-debug-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+crc32-devel", rpm:"rust-gix-features+crc32-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+default-devel", rpm:"rust-gix-features+default-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+document-features-devel", rpm:"rust-gix-features+document-features-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+fast-sha1-devel", rpm:"rust-gix-features+fast-sha1-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+fs-read-dir-devel", rpm:"rust-gix-features+fs-read-dir-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+fs-walkdir-parallel-devel", rpm:"rust-gix-features+fs-walkdir-parallel-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+io-pipe-devel", rpm:"rust-gix-features+io-pipe-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+once_cell-devel", rpm:"rust-gix-features+once_cell-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+parallel-devel", rpm:"rust-gix-features+parallel-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+prodash-devel", rpm:"rust-gix-features+prodash-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+progress-devel", rpm:"rust-gix-features+progress-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+progress-unit-bytes-devel", rpm:"rust-gix-features+progress-unit-bytes-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+progress-unit-human-numbers-devel", rpm:"rust-gix-features+progress-unit-human-numbers-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+rustsha1-devel", rpm:"rust-gix-features+rustsha1-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+tracing-detail-devel", rpm:"rust-gix-features+tracing-detail-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+tracing-devel", rpm:"rust-gix-features+tracing-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+walkdir-devel", rpm:"rust-gix-features+walkdir-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+zlib-devel", rpm:"rust-gix-features+zlib-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+zlib-ng-devel", rpm:"rust-gix-features+zlib-ng-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+zlib-rust-backend-devel", rpm:"rust-gix-features+zlib-rust-backend-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features+zlib-stock-devel", rpm:"rust-gix-features+zlib-stock-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features", rpm:"rust-gix-features~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-features-devel", rpm:"rust-gix-features-devel~0.38.2~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-filter+default-devel", rpm:"rust-gix-filter+default-devel~0.13.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-filter", rpm:"rust-gix-filter~0.13.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-filter-devel", rpm:"rust-gix-filter-devel~0.13.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-fs+default-devel", rpm:"rust-gix-fs+default-devel~0.11.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-fs+serde-devel", rpm:"rust-gix-fs+serde-devel~0.11.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-fs", rpm:"rust-gix-fs~0.11.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-fs-devel", rpm:"rust-gix-fs-devel~0.11.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-glob+default-devel", rpm:"rust-gix-glob+default-devel~0.16.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-glob+document-features-devel", rpm:"rust-gix-glob+document-features-devel~0.16.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-glob+serde-devel", rpm:"rust-gix-glob+serde-devel~0.16.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-glob", rpm:"rust-gix-glob~0.16.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-glob-devel", rpm:"rust-gix-glob-devel~0.16.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-ignore+default-devel", rpm:"rust-gix-ignore+default-devel~0.11.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-ignore+document-features-devel", rpm:"rust-gix-ignore+document-features-devel~0.11.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-ignore+serde-devel", rpm:"rust-gix-ignore+serde-devel~0.11.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-ignore", rpm:"rust-gix-ignore~0.11.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-ignore-devel", rpm:"rust-gix-ignore-devel~0.11.4~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-index+default-devel", rpm:"rust-gix-index+default-devel~0.35.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-index+document-features-devel", rpm:"rust-gix-index+document-features-devel~0.35.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-index+serde-devel", rpm:"rust-gix-index+serde-devel~0.35.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-index", rpm:"rust-gix-index~0.35.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-index-devel", rpm:"rust-gix-index-devel~0.35.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-mailmap+default-devel", rpm:"rust-gix-mailmap+default-devel~0.24.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-mailmap+document-features-devel", rpm:"rust-gix-mailmap+document-features-devel~0.24.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-mailmap+serde-devel", rpm:"rust-gix-mailmap+serde-devel~0.24.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-mailmap", rpm:"rust-gix-mailmap~0.24.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-mailmap-devel", rpm:"rust-gix-mailmap-devel~0.24.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-negotiate+default-devel", rpm:"rust-gix-negotiate+default-devel~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-negotiate", rpm:"rust-gix-negotiate~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-negotiate-devel", rpm:"rust-gix-negotiate-devel~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-object+default-devel", rpm:"rust-gix-object+default-devel~0.44.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-object+document-features-devel", rpm:"rust-gix-object+document-features-devel~0.44.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-object+serde-devel", rpm:"rust-gix-object+serde-devel~0.44.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-object+verbose-object-parsing-errors-devel", rpm:"rust-gix-object+verbose-object-parsing-errors-devel~0.44.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-object", rpm:"rust-gix-object~0.44.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-object-devel", rpm:"rust-gix-object-devel~0.44.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-odb+default-devel", rpm:"rust-gix-odb+default-devel~0.63.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-odb+document-features-devel", rpm:"rust-gix-odb+document-features-devel~0.63.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-odb+serde-devel", rpm:"rust-gix-odb+serde-devel~0.63.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-odb", rpm:"rust-gix-odb~0.63.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-odb-devel", rpm:"rust-gix-odb-devel~0.63.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-pack+default-devel", rpm:"rust-gix-pack+default-devel~0.53.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-pack+document-features-devel", rpm:"rust-gix-pack+document-features-devel~0.53.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-pack+generate-devel", rpm:"rust-gix-pack+generate-devel~0.53.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-pack+object-cache-dynamic-devel", rpm:"rust-gix-pack+object-cache-dynamic-devel~0.53.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-pack+pack-cache-lru-dynamic-devel", rpm:"rust-gix-pack+pack-cache-lru-dynamic-devel~0.53.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-pack+pack-cache-lru-static-devel", rpm:"rust-gix-pack+pack-cache-lru-static-devel~0.53.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-pack+serde-devel", rpm:"rust-gix-pack+serde-devel~0.53.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-pack+streaming-input-devel", rpm:"rust-gix-pack+streaming-input-devel~0.53.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-pack", rpm:"rust-gix-pack~0.53.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-pack-devel", rpm:"rust-gix-pack-devel~0.53.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline+async-io-devel", rpm:"rust-gix-packetline+async-io-devel~0.17.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline+blocking-io-devel", rpm:"rust-gix-packetline+blocking-io-devel~0.17.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline+default-devel", rpm:"rust-gix-packetline+default-devel~0.17.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline+document-features-devel", rpm:"rust-gix-packetline+document-features-devel~0.17.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline+futures-io-devel", rpm:"rust-gix-packetline+futures-io-devel~0.17.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline+futures-lite-devel", rpm:"rust-gix-packetline+futures-lite-devel~0.17.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline+pin-project-lite-devel", rpm:"rust-gix-packetline+pin-project-lite-devel~0.17.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline+serde-devel", rpm:"rust-gix-packetline+serde-devel~0.17.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline", rpm:"rust-gix-packetline~0.17.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline-blocking+async-io-devel", rpm:"rust-gix-packetline-blocking+async-io-devel~0.17.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline-blocking+blocking-io-devel", rpm:"rust-gix-packetline-blocking+blocking-io-devel~0.17.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline-blocking+default-devel", rpm:"rust-gix-packetline-blocking+default-devel~0.17.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline-blocking+document-features-devel", rpm:"rust-gix-packetline-blocking+document-features-devel~0.17.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline-blocking+serde-devel", rpm:"rust-gix-packetline-blocking+serde-devel~0.17.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline-blocking", rpm:"rust-gix-packetline-blocking~0.17.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline-blocking-devel", rpm:"rust-gix-packetline-blocking-devel~0.17.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-packetline-devel", rpm:"rust-gix-packetline-devel~0.17.6~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-path+default-devel", rpm:"rust-gix-path+default-devel~0.10.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-path", rpm:"rust-gix-path~0.10.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-path-devel", rpm:"rust-gix-path-devel~0.10.11~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-pathspec+default-devel", rpm:"rust-gix-pathspec+default-devel~0.7.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-pathspec", rpm:"rust-gix-pathspec~0.7.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-pathspec-devel", rpm:"rust-gix-pathspec-devel~0.7.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-prompt+default-devel", rpm:"rust-gix-prompt+default-devel~0.8.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-prompt", rpm:"rust-gix-prompt~0.8.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-prompt-devel", rpm:"rust-gix-prompt-devel~0.8.7~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-protocol+async-client-devel", rpm:"rust-gix-protocol+async-client-devel~0.45.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-protocol+async-trait-devel", rpm:"rust-gix-protocol+async-trait-devel~0.45.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-protocol+blocking-client-devel", rpm:"rust-gix-protocol+blocking-client-devel~0.45.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-protocol+default-devel", rpm:"rust-gix-protocol+default-devel~0.45.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-protocol+document-features-devel", rpm:"rust-gix-protocol+document-features-devel~0.45.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-protocol+futures-io-devel", rpm:"rust-gix-protocol+futures-io-devel~0.45.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-protocol+futures-lite-devel", rpm:"rust-gix-protocol+futures-lite-devel~0.45.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-protocol+serde-devel", rpm:"rust-gix-protocol+serde-devel~0.45.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-protocol", rpm:"rust-gix-protocol~0.45.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-protocol-devel", rpm:"rust-gix-protocol-devel~0.45.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-ref+default-devel", rpm:"rust-gix-ref+default-devel~0.47.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-ref+document-features-devel", rpm:"rust-gix-ref+document-features-devel~0.47.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-ref+serde-devel", rpm:"rust-gix-ref+serde-devel~0.47.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-ref", rpm:"rust-gix-ref~0.47.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-ref-devel", rpm:"rust-gix-ref-devel~0.47.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-refspec+default-devel", rpm:"rust-gix-refspec+default-devel~0.25.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-refspec", rpm:"rust-gix-refspec~0.25.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-refspec-devel", rpm:"rust-gix-refspec-devel~0.25.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-revision+default-devel", rpm:"rust-gix-revision+default-devel~0.29.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-revision+describe-devel", rpm:"rust-gix-revision+describe-devel~0.29.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-revision+document-features-devel", rpm:"rust-gix-revision+document-features-devel~0.29.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-revision+serde-devel", rpm:"rust-gix-revision+serde-devel~0.29.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-revision", rpm:"rust-gix-revision~0.29.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-revision-devel", rpm:"rust-gix-revision-devel~0.29.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-revwalk+default-devel", rpm:"rust-gix-revwalk+default-devel~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-revwalk", rpm:"rust-gix-revwalk~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-revwalk-devel", rpm:"rust-gix-revwalk-devel~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-sec+default-devel", rpm:"rust-gix-sec+default-devel~0.10.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-sec+document-features-devel", rpm:"rust-gix-sec+document-features-devel~0.10.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-sec+serde-devel", rpm:"rust-gix-sec+serde-devel~0.10.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-sec", rpm:"rust-gix-sec~0.10.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-sec-devel", rpm:"rust-gix-sec-devel~0.10.8~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-status+default-devel", rpm:"rust-gix-status+default-devel~0.13.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-status+document-features-devel", rpm:"rust-gix-status+document-features-devel~0.13.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-status+worktree-rewrites-devel", rpm:"rust-gix-status+worktree-rewrites-devel~0.13.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-status", rpm:"rust-gix-status~0.13.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-status-devel", rpm:"rust-gix-status-devel~0.13.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-submodule+default-devel", rpm:"rust-gix-submodule+default-devel~0.14.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-submodule", rpm:"rust-gix-submodule~0.14.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-submodule-devel", rpm:"rust-gix-submodule-devel~0.14.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-tempfile+default-devel", rpm:"rust-gix-tempfile+default-devel~14.0.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-tempfile+document-features-devel", rpm:"rust-gix-tempfile+document-features-devel~14.0.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-tempfile+hp-hashmap-devel", rpm:"rust-gix-tempfile+hp-hashmap-devel~14.0.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-tempfile+signals-devel", rpm:"rust-gix-tempfile+signals-devel~14.0.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-tempfile", rpm:"rust-gix-tempfile~14.0.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-tempfile-devel", rpm:"rust-gix-tempfile-devel~14.0.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-trace+default-devel", rpm:"rust-gix-trace+default-devel~0.1.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-trace+document-features-devel", rpm:"rust-gix-trace+document-features-devel~0.1.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-trace+tracing-detail-devel", rpm:"rust-gix-trace+tracing-detail-devel~0.1.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-trace+tracing-devel", rpm:"rust-gix-trace+tracing-devel~0.1.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-trace", rpm:"rust-gix-trace~0.1.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-trace-devel", rpm:"rust-gix-trace-devel~0.1.10~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+async-client-devel", rpm:"rust-gix-transport+async-client-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+async-std-devel", rpm:"rust-gix-transport+async-std-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+async-trait-devel", rpm:"rust-gix-transport+async-trait-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+base64-devel", rpm:"rust-gix-transport+base64-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+blocking-client-devel", rpm:"rust-gix-transport+blocking-client-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+curl-devel", rpm:"rust-gix-transport+curl-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+default-devel", rpm:"rust-gix-transport+default-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+document-features-devel", rpm:"rust-gix-transport+document-features-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+futures-io-devel", rpm:"rust-gix-transport+futures-io-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+futures-lite-devel", rpm:"rust-gix-transport+futures-lite-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+gix-credentials-devel", rpm:"rust-gix-transport+gix-credentials-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+http-client-curl-devel", rpm:"rust-gix-transport+http-client-curl-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+http-client-devel", rpm:"rust-gix-transport+http-client-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+http-client-reqwest-devel", rpm:"rust-gix-transport+http-client-reqwest-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+http-client-reqwest-native-tls-devel", rpm:"rust-gix-transport+http-client-reqwest-native-tls-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+http-client-reqwest-rust-tls-devel", rpm:"rust-gix-transport+http-client-reqwest-rust-tls-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+http-client-reqwest-rust-tls-trust-dns-devel", rpm:"rust-gix-transport+http-client-reqwest-rust-tls-trust-dns-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+pin-project-lite-devel", rpm:"rust-gix-transport+pin-project-lite-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+reqwest-devel", rpm:"rust-gix-transport+reqwest-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport+serde-devel", rpm:"rust-gix-transport+serde-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport", rpm:"rust-gix-transport~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-transport-devel", rpm:"rust-gix-transport-devel~0.42.3~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-traverse+default-devel", rpm:"rust-gix-traverse+default-devel~0.41.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-traverse", rpm:"rust-gix-traverse~0.41.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-traverse-devel", rpm:"rust-gix-traverse-devel~0.41.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-url+default-devel", rpm:"rust-gix-url+default-devel~0.27.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-url+document-features-devel", rpm:"rust-gix-url+document-features-devel~0.27.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-url+serde-devel", rpm:"rust-gix-url+serde-devel~0.27.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-url", rpm:"rust-gix-url~0.27.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-url-devel", rpm:"rust-gix-url-devel~0.27.5~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-validate+default-devel", rpm:"rust-gix-validate+default-devel~0.9.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-validate", rpm:"rust-gix-validate~0.9.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-validate-devel", rpm:"rust-gix-validate-devel~0.9.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-worktree+attributes-devel", rpm:"rust-gix-worktree+attributes-devel~0.36.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-worktree+default-devel", rpm:"rust-gix-worktree+default-devel~0.36.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-worktree+document-features-devel", rpm:"rust-gix-worktree+document-features-devel~0.36.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-worktree+serde-devel", rpm:"rust-gix-worktree+serde-devel~0.36.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-worktree", rpm:"rust-gix-worktree~0.36.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-worktree-devel", rpm:"rust-gix-worktree-devel~0.36.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-worktree-state+default-devel", rpm:"rust-gix-worktree-state+default-devel~0.13.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-worktree-state", rpm:"rust-gix-worktree-state~0.13.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-worktree-state-devel", rpm:"rust-gix-worktree-state-devel~0.13.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-worktree-stream+default-devel", rpm:"rust-gix-worktree-stream+default-devel~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-worktree-stream", rpm:"rust-gix-worktree-stream~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gix-worktree-stream-devel", rpm:"rust-gix-worktree-stream-devel~0.15.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-onefetch+default-devel", rpm:"rust-onefetch+default-devel~2.21.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-onefetch+fail-on-deprecated-devel", rpm:"rust-onefetch+fail-on-deprecated-devel~2.21.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-onefetch", rpm:"rust-onefetch~2.21.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-onefetch-debugsource", rpm:"rust-onefetch-debugsource~2.21.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-onefetch-devel", rpm:"rust-onefetch-devel~2.21.0~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+async-io-devel", rpm:"rust-prodash+async-io-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+bytesize-devel", rpm:"rust-prodash+bytesize-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+ctrlc-devel", rpm:"rust-prodash+ctrlc-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+dashmap-devel", rpm:"rust-prodash+dashmap-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+default-devel", rpm:"rust-prodash+default-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+futures-core-devel", rpm:"rust-prodash+futures-core-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+futures-lite-devel", rpm:"rust-prodash+futures-lite-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+human_format-devel", rpm:"rust-prodash+human_format-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+humantime-devel", rpm:"rust-prodash+humantime-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+is-terminal-devel", rpm:"rust-prodash+is-terminal-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+jiff-devel", rpm:"rust-prodash+jiff-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+local-time-devel", rpm:"rust-prodash+local-time-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+log-devel", rpm:"rust-prodash+log-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+parking_lot-devel", rpm:"rust-prodash+parking_lot-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+progress-log-devel", rpm:"rust-prodash+progress-log-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+progress-tree-devel", rpm:"rust-prodash+progress-tree-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+progress-tree-hp-hashmap-devel", rpm:"rust-prodash+progress-tree-hp-hashmap-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+progress-tree-log-devel", rpm:"rust-prodash+progress-tree-log-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+render-line-autoconfigure-devel", rpm:"rust-prodash+render-line-autoconfigure-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+signal-hook-devel", rpm:"rust-prodash+signal-hook-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+unicode-segmentation-devel", rpm:"rust-prodash+unicode-segmentation-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+unicode-width-devel", rpm:"rust-prodash+unicode-width-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+unit-bytes-devel", rpm:"rust-prodash+unit-bytes-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash+unit-human-devel", rpm:"rust-prodash+unit-human-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash", rpm:"rust-prodash~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prodash-devel", rpm:"rust-prodash-devel~29.0.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustsec+default-devel", rpm:"rust-rustsec+default-devel~0.29.3~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustsec+dependency-tree-devel", rpm:"rust-rustsec+dependency-tree-devel~0.29.3~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustsec+git-devel", rpm:"rust-rustsec+git-devel~0.29.3~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustsec+osv-export-devel", rpm:"rust-rustsec+osv-export-devel~0.29.3~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustsec", rpm:"rust-rustsec~0.29.3~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustsec-devel", rpm:"rust-rustsec-devel~0.29.3~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tame-index+default-devel", rpm:"rust-tame-index+default-devel~0.12.0~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tame-index+git-devel", rpm:"rust-tame-index+git-devel~0.12.0~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tame-index+local-builder-devel", rpm:"rust-tame-index+local-builder-devel~0.12.0~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tame-index+local-devel", rpm:"rust-tame-index+local-devel~0.12.0~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tame-index+native-certs-devel", rpm:"rust-tame-index+native-certs-devel~0.12.0~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tame-index+sparse-devel", rpm:"rust-tame-index+sparse-devel~0.12.0~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tame-index", rpm:"rust-tame-index~0.12.0~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tame-index-devel", rpm:"rust-tame-index-devel~0.12.0~3.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+build-devel", rpm:"rust-vergen+build-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+cargo-devel", rpm:"rust-vergen+cargo-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+cargo_metadata-devel", rpm:"rust-vergen+cargo_metadata-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+cfg-if-devel", rpm:"rust-vergen+cfg-if-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+default-devel", rpm:"rust-vergen+default-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+git-devel", rpm:"rust-vergen+git-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+git2-devel", rpm:"rust-vergen+git2-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+git2-rs-devel", rpm:"rust-vergen+git2-rs-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+gitcl-devel", rpm:"rust-vergen+gitcl-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+gitoxide-devel", rpm:"rust-vergen+gitoxide-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+gix-devel", rpm:"rust-vergen+gix-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+regex-devel", rpm:"rust-vergen+regex-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+rustc-devel", rpm:"rust-vergen+rustc-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+rustc_version-devel", rpm:"rust-vergen+rustc_version-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+si-devel", rpm:"rust-vergen+si-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+sysinfo-devel", rpm:"rust-vergen+sysinfo-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+time-devel", rpm:"rust-vergen+time-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen", rpm:"rust-vergen~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen-devel", rpm:"rust-vergen-devel~8.3.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stgit", rpm:"stgit~2.4.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stgit-debuginfo", rpm:"stgit-debuginfo~2.4.12~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stgit-debugsource", rpm:"stgit-debugsource~2.4.12~1.fc42", rls:"FC42"))) {
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
