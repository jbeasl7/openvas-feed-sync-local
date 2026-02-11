# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.1024005799721");
  script_cve_id("CVE-2026-25537", "CVE-2026-25727");
  script_tag(name:"creation_date", value:"2026-02-10 04:50:19 +0000 (Tue, 10 Feb 2026)");
  script_version("2026-02-10T08:18:30+0000");
  script_tag(name:"last_modification", value:"2026-02-10 08:18:30 +0000 (Tue, 10 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-f400579a21)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-f400579a21");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-f400579a21");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2437470");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2437472");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438104");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438135");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438138");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438149");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438158");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438164");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438165");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2026-0007.html");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2026-0008.html");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2026-0009.html");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-25537");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'asciinema, atuin, bustle, envision, glycin, greetd, helix, keylime-agent-rust, maturin, mirrorlist-server, ntpd-rs, rust-add-determinism, rust-afterburn, rust-ambient-id, rust-app-store-connect, rust-bat, rust-below, rust-btrd, rust-busd, rust-bytes, rust-cargo-c, rust-cargo-deny, rust-coreos-installer, rust-crypto-auditing-agent, rust-crypto-auditing-client, rust-crypto-auditing-event-broker, rust-crypto-auditing-log-parser, rust-dua-cli, rust-eif_build, rust-git2, rust-git-delta, rust-git-interactive-rebase-tool, rust-gst-plugin-dav1d, rust-gst-plugin-reqwest, rust-heatseeker, rust-ingredients, rust-jsonwebtoken, rust-lsd, rust-monitord, rust-monitord-exporter, rust-muvm, rust-nu, rust-num-conv, rust-onefetch, rust-oo7-cli, rust-pleaser, rust-pore, rust-pretty-git-prompt, rust-procs, rust-rbspy, rust-rbw, rust-rd-agent, rust-rd-hashd, rust-redlib, rust-resctl-bench, rust-resctl-demo, rust-routinator, rust-sccache, rust-scx_layered, rust-scx_rustland, rust-scx_rusty, rust-sequoia-chameleon-gnupg, rust-sequoia-keystore-server, rust-sequoia-octopus-librnp, rust-sequoia-sq, rust-sevctl, rust-shadow-rs, rust-sigul-pesign-bridge, rust-snpguest, rust-speakersafetyd, rust-tealdeer, rust-time, rust-time-core, rust-time-macros, rust-tokei, rust-weezl, rust-wiremix, rust-ybaas, rustup, sad, tbtools, tuigreet, uv' package(s) announced via the FEDORA-2026-f400579a21 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update the time crate to version 0.3.47.
- Update the time-macros crate to version 0.2.27.
- Update the time-core crate to version 0.1.8.
- Update the num-conv crate to version 0.2.0.
- Update the git2 crate to version 0.20.4.
- Update the bytes crate to version 1.11.1.

Additionally, this update contains rebuilds of applications affected by security advisories:

- bytes: [RUSTSEC-2026-0007]([link moved to references])
- git2: [RUSTSEC-2026-0008]([link moved to references])
- jsonwebtoken: [CVE-2026-25537]([link moved to references])
- time: [RUSTSEC-2026-0009]([link moved to references])

All applications that statically link libgit2 via the `git2` Rust bindings were also rebuilt against the latest version of the `git2` / `libgit2-sys` crates to pull in fixes included in libgit2 between v1.8.1 and v1.9.2.");

  script_tag(name:"affected", value:"'asciinema, atuin, bustle, envision, glycin, greetd, helix, keylime-agent-rust, maturin, mirrorlist-server, ntpd-rs, rust-add-determinism, rust-afterburn, rust-ambient-id, rust-app-store-connect, rust-bat, rust-below, rust-btrd, rust-busd, rust-bytes, rust-cargo-c, rust-cargo-deny, rust-coreos-installer, rust-crypto-auditing-agent, rust-crypto-auditing-client, rust-crypto-auditing-event-broker, rust-crypto-auditing-log-parser, rust-dua-cli, rust-eif_build, rust-git2, rust-git-delta, rust-git-interactive-rebase-tool, rust-gst-plugin-dav1d, rust-gst-plugin-reqwest, rust-heatseeker, rust-ingredients, rust-jsonwebtoken, rust-lsd, rust-monitord, rust-monitord-exporter, rust-muvm, rust-nu, rust-num-conv, rust-onefetch, rust-oo7-cli, rust-pleaser, rust-pore, rust-pretty-git-prompt, rust-procs, rust-rbspy, rust-rbw, rust-rd-agent, rust-rd-hashd, rust-redlib, rust-resctl-bench, rust-resctl-demo, rust-routinator, rust-sccache, rust-scx_layered, rust-scx_rustland, rust-scx_rusty, rust-sequoia-chameleon-gnupg, rust-sequoia-keystore-server, rust-sequoia-octopus-librnp, rust-sequoia-sq, rust-sevctl, rust-shadow-rs, rust-sigul-pesign-bridge, rust-snpguest, rust-speakersafetyd, rust-tealdeer, rust-time, rust-time-core, rust-time-macros, rust-tokei, rust-weezl, rust-wiremix, rust-ybaas, rustup, sad, tbtools, tuigreet, uv' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"add-determinism", rpm:"add-determinism~0.6.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"add-determinism-debuginfo", rpm:"add-determinism-debuginfo~0.6.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"afterburn", rpm:"afterburn~5.10.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"afterburn-debuginfo", rpm:"afterburn-debuginfo~5.10.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"afterburn-dracut", rpm:"afterburn-dracut~5.10.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"app-store-connect", rpm:"app-store-connect~0.5.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"app-store-connect-debuginfo", rpm:"app-store-connect-debuginfo~0.5.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asciinema", rpm:"asciinema~3.0.0~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asciinema-debuginfo", rpm:"asciinema-debuginfo~3.0.0~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asciinema-debugsource", rpm:"asciinema-debugsource~3.0.0~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atuin", rpm:"atuin~18.6.1~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atuin-all-users", rpm:"atuin-all-users~18.6.1~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atuin-debuginfo", rpm:"atuin-debuginfo~18.6.1~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atuin-debugsource", rpm:"atuin-debugsource~18.6.1~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bat", rpm:"bat~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bat-debuginfo", rpm:"bat-debuginfo~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"below", rpm:"below~0.9.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"below-debuginfo", rpm:"below-debuginfo~0.9.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btrd", rpm:"btrd~0.5.3~12.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btrd-debuginfo", rpm:"btrd-debuginfo~0.5.3~12.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"build-reproducibility-srpm-macros", rpm:"build-reproducibility-srpm-macros~0.6.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busd", rpm:"busd~0.3.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"busd-debuginfo", rpm:"busd-debuginfo~0.3.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bustle", rpm:"bustle~0.13.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bustle-debuginfo", rpm:"bustle-debuginfo~0.13.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bustle-debugsource", rpm:"bustle-debugsource~0.13.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-c", rpm:"cargo-c~0.10.18~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-c-debuginfo", rpm:"cargo-c-debuginfo~0.10.18~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-deny", rpm:"cargo-deny~0.18.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-deny-debuginfo", rpm:"cargo-deny-debuginfo~0.18.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer", rpm:"coreos-installer~0.25.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-bootinfra", rpm:"coreos-installer-bootinfra~0.25.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-bootinfra-debuginfo", rpm:"coreos-installer-bootinfra-debuginfo~0.25.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-debuginfo", rpm:"coreos-installer-debuginfo~0.25.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-dracut", rpm:"coreos-installer-dracut~0.25.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-agent", rpm:"crypto-auditing-agent~0.2.4~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-agent-debuginfo", rpm:"crypto-auditing-agent-debuginfo~0.2.4~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-client", rpm:"crypto-auditing-client~0.2.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-client-debuginfo", rpm:"crypto-auditing-client-debuginfo~0.2.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-event-broker", rpm:"crypto-auditing-event-broker~0.2.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-event-broker-debuginfo", rpm:"crypto-auditing-event-broker-debuginfo~0.2.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-log-parser", rpm:"crypto-auditing-log-parser~0.2.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-log-parser-debuginfo", rpm:"crypto-auditing-log-parser-debuginfo~0.2.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dua-cli", rpm:"dua-cli~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dua-cli-debuginfo", rpm:"dua-cli-debuginfo~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eif_build", rpm:"eif_build~0.2.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eif_build-debuginfo", rpm:"eif_build-debuginfo~0.2.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"envision", rpm:"envision~3.2.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"envision-debuginfo", rpm:"envision-debuginfo~3.2.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"envision-debugsource", rpm:"envision-debugsource~3.2.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"envision-monado", rpm:"envision-monado~3.2.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"envision-wivrn", rpm:"envision-wivrn~3.2.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"envision-xrizer", rpm:"envision-xrizer~3.2.0~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-delta", rpm:"git-delta~0.18.2~13.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-delta-debuginfo", rpm:"git-delta-debuginfo~0.18.2~13.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-interactive-rebase-tool", rpm:"git-interactive-rebase-tool~2.4.1~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-interactive-rebase-tool-debuginfo", rpm:"git-interactive-rebase-tool-debuginfo~2.4.1~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin", rpm:"glycin~2.0.5~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-debuginfo", rpm:"glycin-debuginfo~2.0.5~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-debugsource", rpm:"glycin-debugsource~2.0.5~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-devel", rpm:"glycin-devel~2.0.5~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-gtk4-devel", rpm:"glycin-gtk4-devel~2.0.5~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-gtk4-libs", rpm:"glycin-gtk4-libs~2.0.5~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-gtk4-libs-debuginfo", rpm:"glycin-gtk4-libs-debuginfo~2.0.5~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-libs", rpm:"glycin-libs~2.0.5~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-libs-debuginfo", rpm:"glycin-libs-debuginfo~2.0.5~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-loaders", rpm:"glycin-loaders~2.0.5~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-loaders-debuginfo", rpm:"glycin-loaders-debuginfo~2.0.5~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-thumbnailer", rpm:"glycin-thumbnailer~2.0.5~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-thumbnailer-debuginfo", rpm:"glycin-thumbnailer-debuginfo~2.0.5~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"greetd", rpm:"greetd~0.10.3~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"greetd-debuginfo", rpm:"greetd-debuginfo~0.10.3~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"greetd-debugsource", rpm:"greetd-debugsource~0.10.3~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"greetd-fakegreet", rpm:"greetd-fakegreet~0.10.3~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"greetd-fakegreet-debuginfo", rpm:"greetd-fakegreet-debuginfo~0.10.3~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"greetd-selinux", rpm:"greetd-selinux~0.10.3~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-dav1d", rpm:"gstreamer1-plugin-dav1d~0.14.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-dav1d-debuginfo", rpm:"gstreamer1-plugin-dav1d-debuginfo~0.14.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-reqwest", rpm:"gstreamer1-plugin-reqwest~0.14.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-reqwest-debuginfo", rpm:"gstreamer1-plugin-reqwest-debuginfo~0.14.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heatseeker", rpm:"heatseeker~1.7.3~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heatseeker-debuginfo", rpm:"heatseeker-debuginfo~1.7.3~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helix", rpm:"helix~25.07.1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helix-debuginfo", rpm:"helix-debuginfo~25.07.1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helix-debugsource", rpm:"helix-debugsource~25.07.1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ingredients", rpm:"ingredients~0.2.2~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ingredients-debuginfo", rpm:"ingredients-debuginfo~0.2.2~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust", rpm:"keylime-agent-rust~0.2.8~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-common", rpm:"keylime-agent-rust-common~0.2.8~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-debuginfo", rpm:"keylime-agent-rust-debuginfo~0.2.8~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-debugsource", rpm:"keylime-agent-rust-debugsource~0.2.8~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-ima-emulator", rpm:"keylime-agent-rust-ima-emulator~0.2.8~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-ima-emulator-debuginfo", rpm:"keylime-agent-rust-ima-emulator-debuginfo~0.2.8~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-push", rpm:"keylime-agent-rust-push~0.2.8~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-push-debuginfo", rpm:"keylime-agent-rust-push-debuginfo~0.2.8~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lsd", rpm:"lsd~1.2.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lsd-debuginfo", rpm:"lsd-debuginfo~1.2.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maturin", rpm:"maturin~1.9.6~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maturin-debuginfo", rpm:"maturin-debuginfo~1.9.6~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maturin-debugsource", rpm:"maturin-debugsource~1.9.6~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mirrorlist-server", rpm:"mirrorlist-server~3.0.8~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mirrorlist-server-debuginfo", rpm:"mirrorlist-server-debuginfo~3.0.8~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mirrorlist-server-debugsource", rpm:"mirrorlist-server-debugsource~3.0.8~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"monitord", rpm:"monitord~0.12.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"monitord-debuginfo", rpm:"monitord-debuginfo~0.12.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"monitord-exporter", rpm:"monitord-exporter~0.4.1~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"monitord-exporter-debuginfo", rpm:"monitord-exporter-debuginfo~0.4.1~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"muvm", rpm:"muvm~0.4.1~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"muvm-debuginfo", rpm:"muvm-debuginfo~0.4.1~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpd-rs", rpm:"ntpd-rs~1.6.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpd-rs-debuginfo", rpm:"ntpd-rs-debuginfo~1.6.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpd-rs-debugsource", rpm:"ntpd-rs-debugsource~1.6.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nu", rpm:"nu~0.99.1~16.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nu-debuginfo", rpm:"nu-debuginfo~0.99.1~16.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"onefetch", rpm:"onefetch~2.26.1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"onefetch-debuginfo", rpm:"onefetch-debuginfo~2.26.1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oo7-cli", rpm:"oo7-cli~0.4.3~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oo7-cli-debuginfo", rpm:"oo7-cli-debuginfo~0.4.3~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pleaser", rpm:"pleaser~0.5.6~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pleaser-debuginfo", rpm:"pleaser-debuginfo~0.5.6~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pore", rpm:"pore~0.1.17~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pore-debuginfo", rpm:"pore-debuginfo~0.1.17~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pretty-git-prompt", rpm:"pretty-git-prompt~0.2.2~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pretty-git-prompt-debuginfo", rpm:"pretty-git-prompt-debuginfo~0.2.2~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procs", rpm:"procs~0.14.10~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procs-debuginfo", rpm:"procs-debuginfo~0.14.10~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv", rpm:"python3-uv~0.9.30~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbspy", rpm:"rbspy~0.34.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbspy-debuginfo", rpm:"rbspy-debuginfo~0.34.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbw", rpm:"rbw~1.13.2~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbw-debuginfo", rpm:"rbw-debuginfo~1.13.2~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rd-agent", rpm:"rd-agent~2.2.5~14.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rd-agent-data", rpm:"rd-agent-data~2.2.5~14.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rd-agent-debuginfo", rpm:"rd-agent-debuginfo~2.2.5~14.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rd-agent-selinux", rpm:"rd-agent-selinux~2.2.5~14.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rd-hashd", rpm:"rd-hashd~2.2.5~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rd-hashd-debuginfo", rpm:"rd-hashd-debuginfo~2.2.5~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redlib", rpm:"redlib~0.35.1~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redlib-debuginfo", rpm:"redlib-debuginfo~0.35.1~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resctl-bench", rpm:"resctl-bench~2.2.5~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resctl-bench-debuginfo", rpm:"resctl-bench-debuginfo~2.2.5~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resctl-demo", rpm:"resctl-demo~2.2.5~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resctl-demo-debuginfo", rpm:"resctl-demo-debuginfo~2.2.5~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"routinator", rpm:"routinator~0.14.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"routinator-debuginfo", rpm:"routinator-debuginfo~0.14.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-add-determinism", rpm:"rust-add-determinism~0.6.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-add-determinism-debugsource", rpm:"rust-add-determinism-debugsource~0.6.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-afterburn", rpm:"rust-afterburn~5.10.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-afterburn-debugsource", rpm:"rust-afterburn-debugsource~5.10.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ambient-id+astral-reqwest-middleware-devel", rpm:"rust-ambient-id+astral-reqwest-middleware-devel~0.0.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ambient-id+default-devel", rpm:"rust-ambient-id+default-devel~0.0.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ambient-id+reqwest-middleware-devel", rpm:"rust-ambient-id+reqwest-middleware-devel~0.0.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ambient-id", rpm:"rust-ambient-id~0.0.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ambient-id-devel", rpm:"rust-ambient-id-devel~0.0.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-app-store-connect+default-devel", rpm:"rust-app-store-connect+default-devel~0.5.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-app-store-connect", rpm:"rust-app-store-connect~0.5.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-app-store-connect-debugsource", rpm:"rust-app-store-connect-debugsource~0.5.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-app-store-connect-devel", rpm:"rust-app-store-connect-devel~0.5.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+application-devel", rpm:"rust-bat+application-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+bugreport-devel", rpm:"rust-bat+bugreport-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+build-assets-devel", rpm:"rust-bat+build-assets-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+clap-devel", rpm:"rust-bat+clap-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+default-devel", rpm:"rust-bat+default-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+etcetera-devel", rpm:"rust-bat+etcetera-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+git-devel", rpm:"rust-bat+git-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+git2-devel", rpm:"rust-bat+git2-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+grep-cli-devel", rpm:"rust-bat+grep-cli-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+minimal-application-devel", rpm:"rust-bat+minimal-application-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+paging-devel", rpm:"rust-bat+paging-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+regex-devel", rpm:"rust-bat+regex-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+regex-fancy-devel", rpm:"rust-bat+regex-fancy-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+regex-onig-devel", rpm:"rust-bat+regex-onig-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+shell-words-devel", rpm:"rust-bat+shell-words-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+walkdir-devel", rpm:"rust-bat+walkdir-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+wild-devel", rpm:"rust-bat+wild-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat", rpm:"rust-bat~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat-debugsource", rpm:"rust-bat-debugsource~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat-devel", rpm:"rust-bat-devel~0.25.0~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-below", rpm:"rust-below~0.9.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-below-debugsource", rpm:"rust-below-debugsource~0.9.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-btrd+default-devel", rpm:"rust-btrd+default-devel~0.5.3~12.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-btrd", rpm:"rust-btrd~0.5.3~12.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-btrd-debugsource", rpm:"rust-btrd-debugsource~0.5.3~12.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-btrd-devel", rpm:"rust-btrd-devel~0.5.3~12.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-busd+default-devel", rpm:"rust-busd+default-devel~0.3.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-busd+tracing-subscriber-devel", rpm:"rust-busd+tracing-subscriber-devel~0.3.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-busd", rpm:"rust-busd~0.3.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-busd-debugsource", rpm:"rust-busd-debugsource~0.3.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-busd-devel", rpm:"rust-busd-devel~0.3.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bytes+default-devel", rpm:"rust-bytes+default-devel~1.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bytes+extra-platforms-devel", rpm:"rust-bytes+extra-platforms-devel~1.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bytes+serde-devel", rpm:"rust-bytes+serde-devel~1.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bytes+std-devel", rpm:"rust-bytes+std-devel~1.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bytes", rpm:"rust-bytes~1.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bytes-devel", rpm:"rust-bytes-devel~1.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c+default-devel", rpm:"rust-cargo-c+default-devel~0.10.18~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c", rpm:"rust-cargo-c~0.10.18~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c-debugsource", rpm:"rust-cargo-c-debugsource~0.10.18~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c-devel", rpm:"rust-cargo-c-devel~0.10.18~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny+default-devel", rpm:"rust-cargo-deny+default-devel~0.18.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny+native-certs-devel", rpm:"rust-cargo-deny+native-certs-devel~0.18.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny", rpm:"rust-cargo-deny~0.18.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny-debugsource", rpm:"rust-cargo-deny-debugsource~0.18.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny-devel", rpm:"rust-cargo-deny-devel~0.18.9~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer", rpm:"rust-coreos-installer~0.25.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer-debuginfo", rpm:"rust-coreos-installer-debuginfo~0.25.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer-debugsource", rpm:"rust-coreos-installer-debugsource~0.25.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-agent", rpm:"rust-crypto-auditing-agent~0.2.4~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-agent-debugsource", rpm:"rust-crypto-auditing-agent-debugsource~0.2.4~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-client", rpm:"rust-crypto-auditing-client~0.2.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-client-debugsource", rpm:"rust-crypto-auditing-client-debugsource~0.2.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-event-broker", rpm:"rust-crypto-auditing-event-broker~0.2.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-event-broker-debugsource", rpm:"rust-crypto-auditing-event-broker-debugsource~0.2.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-log-parser", rpm:"rust-crypto-auditing-log-parser~0.2.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-log-parser-debugsource", rpm:"rust-crypto-auditing-log-parser-debugsource~0.2.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+crosstermion-devel", rpm:"rust-dua-cli+crosstermion-devel~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+default-devel", rpm:"rust-dua-cli+default-devel~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+open-devel", rpm:"rust-dua-cli+open-devel~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+trash-devel", rpm:"rust-dua-cli+trash-devel~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+trash-move-devel", rpm:"rust-dua-cli+trash-move-devel~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+tui-crossplatform-devel", rpm:"rust-dua-cli+tui-crossplatform-devel~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+tui-devel", rpm:"rust-dua-cli+tui-devel~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+tui-react-devel", rpm:"rust-dua-cli+tui-react-devel~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+unicode-segmentation-devel", rpm:"rust-dua-cli+unicode-segmentation-devel~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+unicode-width-devel", rpm:"rust-dua-cli+unicode-width-devel~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli", rpm:"rust-dua-cli~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli-debugsource", rpm:"rust-dua-cli-debugsource~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli-devel", rpm:"rust-dua-cli-devel~2.32.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eif_build", rpm:"rust-eif_build~0.2.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eif_build-debugsource", rpm:"rust-eif_build-debugsource~0.2.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-delta", rpm:"rust-git-delta~0.18.2~13.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-delta-debugsource", rpm:"rust-git-delta-debugsource~0.18.2~13.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-interactive-rebase-tool", rpm:"rust-git-interactive-rebase-tool~2.4.1~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-interactive-rebase-tool-debugsource", rpm:"rust-git-interactive-rebase-tool-debugsource~2.4.1~15.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+default-devel", rpm:"rust-git2+default-devel~0.20.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+https-devel", rpm:"rust-git2+https-devel~0.20.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+openssl-probe-devel", rpm:"rust-git2+openssl-probe-devel~0.20.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+openssl-sys-devel", rpm:"rust-git2+openssl-sys-devel~0.20.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+ssh-devel", rpm:"rust-git2+ssh-devel~0.20.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+unstable-devel", rpm:"rust-git2+unstable-devel~0.20.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+vendored-libgit2-devel", rpm:"rust-git2+vendored-libgit2-devel~0.20.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2", rpm:"rust-git2~0.20.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2-devel", rpm:"rust-git2-devel~0.20.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-dav1d+capi-devel", rpm:"rust-gst-plugin-dav1d+capi-devel~0.14.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-dav1d+default-devel", rpm:"rust-gst-plugin-dav1d+default-devel~0.14.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-dav1d+doc-devel", rpm:"rust-gst-plugin-dav1d+doc-devel~0.14.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-dav1d+static-devel", rpm:"rust-gst-plugin-dav1d+static-devel~0.14.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-dav1d", rpm:"rust-gst-plugin-dav1d~0.14.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-dav1d-debugsource", rpm:"rust-gst-plugin-dav1d-debugsource~0.14.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-dav1d-devel", rpm:"rust-gst-plugin-dav1d-devel~0.14.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+capi-devel", rpm:"rust-gst-plugin-reqwest+capi-devel~0.14.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+default-devel", rpm:"rust-gst-plugin-reqwest+default-devel~0.14.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+doc-devel", rpm:"rust-gst-plugin-reqwest+doc-devel~0.14.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+static-devel", rpm:"rust-gst-plugin-reqwest+static-devel~0.14.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest", rpm:"rust-gst-plugin-reqwest~0.14.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest-debugsource", rpm:"rust-gst-plugin-reqwest-debugsource~0.14.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest-devel", rpm:"rust-gst-plugin-reqwest-devel~0.14.3~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-heatseeker", rpm:"rust-heatseeker~1.7.3~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-heatseeker-debugsource", rpm:"rust-heatseeker-debugsource~1.7.3~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ingredients+cli-devel", rpm:"rust-ingredients+cli-devel~0.2.2~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ingredients+default-devel", rpm:"rust-ingredients+default-devel~0.2.2~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ingredients", rpm:"rust-ingredients~0.2.2~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ingredients-debugsource", rpm:"rust-ingredients-debugsource~0.2.2~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ingredients-devel", rpm:"rust-ingredients-devel~0.2.2~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-jsonwebtoken+default-devel", rpm:"rust-jsonwebtoken+default-devel~9.3.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-jsonwebtoken+pem-devel", rpm:"rust-jsonwebtoken+pem-devel~9.3.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-jsonwebtoken+simple_asn1-devel", rpm:"rust-jsonwebtoken+simple_asn1-devel~9.3.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-jsonwebtoken+use_pem-devel", rpm:"rust-jsonwebtoken+use_pem-devel~9.3.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-jsonwebtoken", rpm:"rust-jsonwebtoken~9.3.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-jsonwebtoken-devel", rpm:"rust-jsonwebtoken-devel~9.3.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lsd", rpm:"rust-lsd~1.2.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lsd-debugsource", rpm:"rust-lsd-debugsource~1.2.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-monitord+default-devel", rpm:"rust-monitord+default-devel~0.12.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-monitord", rpm:"rust-monitord~0.12.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-monitord-debugsource", rpm:"rust-monitord-debugsource~0.12.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-monitord-devel", rpm:"rust-monitord-devel~0.12.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-monitord-exporter+default-devel", rpm:"rust-monitord-exporter+default-devel~0.4.1~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-monitord-exporter", rpm:"rust-monitord-exporter~0.4.1~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-monitord-exporter-debugsource", rpm:"rust-monitord-exporter-debugsource~0.4.1~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-monitord-exporter-devel", rpm:"rust-monitord-exporter-devel~0.4.1~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-muvm", rpm:"rust-muvm~0.4.1~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-muvm-debugsource", rpm:"rust-muvm-debugsource~0.4.1~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu", rpm:"rust-nu~0.99.1~16.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-debugsource", rpm:"rust-nu-debugsource~0.99.1~16.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-num-conv+default-devel", rpm:"rust-num-conv+default-devel~0.2.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-num-conv", rpm:"rust-num-conv~0.2.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-num-conv-devel", rpm:"rust-num-conv-devel~0.2.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-onefetch", rpm:"rust-onefetch~2.26.1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-onefetch-debugsource", rpm:"rust-onefetch-debugsource~2.26.1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oo7-cli", rpm:"rust-oo7-cli~0.4.3~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oo7-cli-debugsource", rpm:"rust-oo7-cli-debugsource~0.4.3~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pleaser+default-devel", rpm:"rust-pleaser+default-devel~0.5.6~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pleaser", rpm:"rust-pleaser~0.5.6~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pleaser-debugsource", rpm:"rust-pleaser-debugsource~0.5.6~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pleaser-devel", rpm:"rust-pleaser-devel~0.5.6~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore+default-devel", rpm:"rust-pore+default-devel~0.1.17~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore", rpm:"rust-pore~0.1.17~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore-debugsource", rpm:"rust-pore-debugsource~0.1.17~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore-devel", rpm:"rust-pore-devel~0.1.17~11.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pretty-git-prompt", rpm:"rust-pretty-git-prompt~0.2.2~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pretty-git-prompt-debugsource", rpm:"rust-pretty-git-prompt-debugsource~0.2.2~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-procs", rpm:"rust-procs~0.14.10~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-procs-debugsource", rpm:"rust-procs-debugsource~0.14.10~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rbspy+default-devel", rpm:"rust-rbspy+default-devel~0.34.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rbspy", rpm:"rust-rbspy~0.34.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rbspy-debugsource", rpm:"rust-rbspy-debugsource~0.34.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rbspy-devel", rpm:"rust-rbspy-devel~0.34.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rbw", rpm:"rust-rbw~1.13.2~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rbw-debugsource", rpm:"rust-rbw-debugsource~1.13.2~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rd-agent", rpm:"rust-rd-agent~2.2.5~14.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rd-agent-debugsource", rpm:"rust-rd-agent-debugsource~2.2.5~14.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rd-hashd", rpm:"rust-rd-hashd~2.2.5~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rd-hashd-debugsource", rpm:"rust-rd-hashd-debugsource~2.2.5~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-redlib", rpm:"rust-redlib~0.35.1~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-redlib-debugsource", rpm:"rust-redlib-debugsource~0.35.1~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-resctl-bench", rpm:"rust-resctl-bench~2.2.5~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-resctl-bench-debugsource", rpm:"rust-resctl-bench-debugsource~2.2.5~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-resctl-demo", rpm:"rust-resctl-demo~2.2.5~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-resctl-demo-debugsource", rpm:"rust-resctl-demo-debugsource~2.2.5~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+arbitrary-devel", rpm:"rust-routinator+arbitrary-devel~0.14.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+default-devel", rpm:"rust-routinator+default-devel~0.14.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+native-tls-devel", rpm:"rust-routinator+native-tls-devel~0.14.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+rta-devel", rpm:"rust-routinator+rta-devel~0.14.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+socks-devel", rpm:"rust-routinator+socks-devel~0.14.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+ui-devel", rpm:"rust-routinator+ui-devel~0.14.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator", rpm:"rust-routinator~0.14.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator-debugsource", rpm:"rust-routinator-debugsource~0.14.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator-devel", rpm:"rust-routinator-devel~0.14.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sccache", rpm:"rust-sccache~0.13.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sccache-debugsource", rpm:"rust-sccache-debugsource~0.13.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_layered", rpm:"rust-scx_layered~0.0.6~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_layered-debugsource", rpm:"rust-scx_layered-debugsource~0.0.6~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_rustland", rpm:"rust-scx_rustland~0.0.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_rustland-debugsource", rpm:"rust-scx_rustland-debugsource~0.0.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_rusty", rpm:"rust-scx_rusty~0.5.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_rusty-debugsource", rpm:"rust-scx_rusty-debugsource~0.5.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-chameleon-gnupg", rpm:"rust-sequoia-chameleon-gnupg~0.13.1~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-chameleon-gnupg-debugsource", rpm:"rust-sequoia-chameleon-gnupg-debugsource~0.13.1~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-keystore-server", rpm:"rust-sequoia-keystore-server~0.2.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-keystore-server-debugsource", rpm:"rust-sequoia-keystore-server-debugsource~0.2.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-octopus-librnp", rpm:"rust-sequoia-octopus-librnp~1.11.1~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-octopus-librnp-debugsource", rpm:"rust-sequoia-octopus-librnp-debugsource~1.11.1~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq", rpm:"rust-sequoia-sq~1.3.1~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq-debugsource", rpm:"rust-sequoia-sq-debugsource~1.3.1~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sevctl", rpm:"rust-sevctl~0.6.2~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sevctl-debugsource", rpm:"rust-sevctl-debugsource~0.6.2~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-shadow-rs+default-devel", rpm:"rust-shadow-rs+default-devel~0.8.1~14.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-shadow-rs+git2-devel", rpm:"rust-shadow-rs+git2-devel~0.8.1~14.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-shadow-rs", rpm:"rust-shadow-rs~0.8.1~14.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-shadow-rs-devel", rpm:"rust-shadow-rs-devel~0.8.1~14.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sigul-pesign-bridge", rpm:"rust-sigul-pesign-bridge~0.5.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sigul-pesign-bridge-debugsource", rpm:"rust-sigul-pesign-bridge-debugsource~0.5.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-snpguest", rpm:"rust-snpguest~0.9.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-snpguest-debugsource", rpm:"rust-snpguest-debugsource~0.9.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-speakersafetyd", rpm:"rust-speakersafetyd~1.0.2~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-speakersafetyd-debugsource", rpm:"rust-speakersafetyd-debugsource~1.0.2~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tealdeer", rpm:"rust-tealdeer~1.7.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tealdeer-debugsource", rpm:"rust-tealdeer-debugsource~1.7.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+alloc-devel", rpm:"rust-time+alloc-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+default-devel", rpm:"rust-time+default-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+formatting-devel", rpm:"rust-time+formatting-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+large-dates-devel", rpm:"rust-time+large-dates-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+local-offset-devel", rpm:"rust-time+local-offset-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+macros-devel", rpm:"rust-time+macros-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+parsing-devel", rpm:"rust-time+parsing-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+quickcheck-devel", rpm:"rust-time+quickcheck-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+rand-devel", rpm:"rust-time+rand-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+rand08-devel", rpm:"rust-time+rand08-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+rand09-devel", rpm:"rust-time+rand09-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+serde-devel", rpm:"rust-time+serde-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+serde-human-readable-devel", rpm:"rust-time+serde-human-readable-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+serde-well-known-devel", rpm:"rust-time+serde-well-known-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time+std-devel", rpm:"rust-time+std-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time", rpm:"rust-time~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time-core+default-devel", rpm:"rust-time-core+default-devel~0.1.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time-core+large-dates-devel", rpm:"rust-time-core+large-dates-devel~0.1.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time-core", rpm:"rust-time-core~0.1.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time-core-devel", rpm:"rust-time-core-devel~0.1.8~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time-devel", rpm:"rust-time-devel~0.3.47~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time-macros+default-devel", rpm:"rust-time-macros+default-devel~0.2.27~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time-macros+formatting-devel", rpm:"rust-time-macros+formatting-devel~0.2.27~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time-macros+large-dates-devel", rpm:"rust-time-macros+large-dates-devel~0.2.27~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time-macros+parsing-devel", rpm:"rust-time-macros+parsing-devel~0.2.27~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time-macros+serde-devel", rpm:"rust-time-macros+serde-devel~0.2.27~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time-macros", rpm:"rust-time-macros~0.2.27~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-time-macros-devel", rpm:"rust-time-macros-devel~0.2.27~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+all-devel", rpm:"rust-tokei+all-devel~14.0.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+cbor-devel", rpm:"rust-tokei+cbor-devel~14.0.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+cli-devel", rpm:"rust-tokei+cli-devel~14.0.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+default-devel", rpm:"rust-tokei+default-devel~14.0.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+yaml-devel", rpm:"rust-tokei+yaml-devel~14.0.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei", rpm:"rust-tokei~14.0.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei-debugsource", rpm:"rust-tokei-debugsource~14.0.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei-devel", rpm:"rust-tokei-devel~14.0.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl+alloc-devel", rpm:"rust-weezl+alloc-devel~0.1.12~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl+async-devel", rpm:"rust-weezl+async-devel~0.1.12~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl+default-devel", rpm:"rust-weezl+default-devel~0.1.12~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl+futures-devel", rpm:"rust-weezl+futures-devel~0.1.12~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl+std-devel", rpm:"rust-weezl+std-devel~0.1.12~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl", rpm:"rust-weezl~0.1.12~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl-debugsource", rpm:"rust-weezl-debugsource~0.1.12~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl-devel", rpm:"rust-weezl-devel~0.1.12~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wiremix", rpm:"rust-wiremix~0.7.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-wiremix-debugsource", rpm:"rust-wiremix-debugsource~0.7.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ybaas", rpm:"rust-ybaas~0.0.19~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ybaas-debugsource", rpm:"rust-ybaas-debugsource~0.0.19~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustup", rpm:"rustup~1.28.2~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustup-debuginfo", rpm:"rustup-debuginfo~1.28.2~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustup-debugsource", rpm:"rustup-debugsource~1.28.2~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sad", rpm:"sad~0.4.32~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sad-debuginfo", rpm:"sad-debuginfo~0.4.32~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sad-debugsource", rpm:"sad-debugsource~0.4.32~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sccache", rpm:"sccache~0.13.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sccache-debuginfo", rpm:"sccache-debuginfo~0.13.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_layered", rpm:"scx_layered~0.0.6~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_layered-debuginfo", rpm:"scx_layered-debuginfo~0.0.6~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_rustland", rpm:"scx_rustland~0.0.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_rustland-debuginfo", rpm:"scx_rustland-debuginfo~0.0.3~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_rusty", rpm:"scx_rusty~0.5.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_rusty-debuginfo", rpm:"scx_rusty-debuginfo~0.5.4~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-chameleon-gnupg", rpm:"sequoia-chameleon-gnupg~0.13.1~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-chameleon-gnupg-debuginfo", rpm:"sequoia-chameleon-gnupg-debuginfo~0.13.1~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-keystore-server", rpm:"sequoia-keystore-server~0.2.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-keystore-server-debuginfo", rpm:"sequoia-keystore-server-debuginfo~0.2.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-octopus-librnp", rpm:"sequoia-octopus-librnp~1.11.1~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-octopus-librnp-debuginfo", rpm:"sequoia-octopus-librnp-debuginfo~1.11.1~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq", rpm:"sequoia-sq~1.3.1~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq-debuginfo", rpm:"sequoia-sq-debuginfo~1.3.1~10.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sevctl", rpm:"sevctl~0.6.2~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sevctl-debuginfo", rpm:"sevctl-debuginfo~0.6.2~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sigul-pesign-bridge", rpm:"sigul-pesign-bridge~0.5.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sigul-pesign-bridge-debuginfo", rpm:"sigul-pesign-bridge-debuginfo~0.5.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snpguest", rpm:"snpguest~0.9.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snpguest-debuginfo", rpm:"snpguest-debuginfo~0.9.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"speakersafetyd", rpm:"speakersafetyd~1.0.2~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"speakersafetyd-debuginfo", rpm:"speakersafetyd-debuginfo~1.0.2~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tbtools", rpm:"tbtools~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tbtools-debuginfo", rpm:"tbtools-debuginfo~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tbtools-debugsource", rpm:"tbtools-debugsource~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tealdeer", rpm:"tealdeer~1.7.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tealdeer-debuginfo", rpm:"tealdeer-debuginfo~1.7.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tokei", rpm:"tokei~14.0.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tokei-debuginfo", rpm:"tokei-debuginfo~14.0.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tuigreet", rpm:"tuigreet~0.9.1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tuigreet-debuginfo", rpm:"tuigreet-debuginfo~0.9.1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tuigreet-debugsource", rpm:"tuigreet-debugsource~0.9.1~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv", rpm:"uv~0.9.30~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debuginfo", rpm:"uv-debuginfo~0.9.30~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debugsource", rpm:"uv-debugsource~0.9.30~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"weezl", rpm:"weezl~0.1.12~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"weezl-debuginfo", rpm:"weezl-debuginfo~0.1.12~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wiremix", rpm:"wiremix~0.7.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wiremix-debuginfo", rpm:"wiremix-debuginfo~0.7.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ybaas", rpm:"ybaas~0.0.19~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ybaas-debuginfo", rpm:"ybaas-debuginfo~0.0.19~6.fc43", rls:"FC43"))) {
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
