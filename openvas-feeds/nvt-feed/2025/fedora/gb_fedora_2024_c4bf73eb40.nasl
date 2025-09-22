# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.99498102731019840");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-c4bf73eb40)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c4bf73eb40");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-c4bf73eb40");
  script_xref(name:"URL", value:"https://github.com/gtk-rs/gtk-rs-core/pull/1343");
  script_xref(name:"URL", value:"https://github.com/rust-lang/hashbrown/pull/511");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2024-0332.html");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2024-0336.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glycin-loaders, gnome-tour, helix, helvum, libipuz, loupe, maturin, ntpd-rs, ruff, rust2rpm-helper, rust-add-determinism, rust-afterburn, rust-alacritty, rust-asahi-btsync, rust-asahi-nvram, rust-asahi-wifisync, rust-askalono-cli, rust-b3sum, rust-bat, rust-bindgen-cli, rust-blsctl, rust-bodhi-cli, rust-btrd, rust-cargo-deny, rust-cargo-insta, rust-cargo-readme, rust-cbindgen, rust-cfonts, rust-choosier, rust-clang-tidy-sarif, rust-clippy-sarif, rust-comrak, rust-copydeps, rust-coreos-installer, rust-count-zeroes, rust-cpc, rust-crypto-auditing-agent, rust-crypto-auditing-client, rust-crypto-auditing-event-broker, rust-crypto-auditing-log-parser, rust-desed, rust-difftastic, rust-diskonaut, rust-docopt, rust-dolby_vision, rust-dotenvy, rust-dua-cli, rust-dutree, rust-elfcat, rust-erdtree, rust-eza, rust-fd-find, rust-fedora-update-feedback, rust-gimoji, rust-git-delta, rust-gitui, rust-gst-plugin-gif, rust-gst-plugin-gtk4, rust-gst-plugin-reqwest, rust-hadolint-sarif, rust-handlebars, rust-heatseeker, rust-hexyl, rust-hyperfine, rust-ifcfg-devname, rust-is_ci, rust-jql, rust-kdotool, rust-krunvm, rust-leb128, rust-libcramjam, rust-lino, rust-local_ipaddress, rust-lscolors, rust-lsd, rust-mdsh, rust-names, rust-navi, rust-nu, rust-nu-utils, rust-oxipng, rust-pleaser, rust-pore, rust-prefixdevname, rust-pretty-bytes, rust-pretty-git-prompt, rust-procs, rust-pulldown-cmark, rust-python-launcher, rust-rav1e, rust-rbspy, rust-rd-agent, rust-rd-hashd, rust-resctl-bench, rust-resctl-demo, rust-ripgrep, rust-routinator, rust-routinator-ui, rust-rpick, rust-rpki, rust-rpm-sequoia, rust-rustcat, rust-sarif-fmt, rust-scx_layered, rust-scx_rustland, rust-scx_rusty, rust-sd, rust-sequoia-chameleon-gnupg, rust-sequoia-keyring-linter, rust-sequoia-octopus-librnp, rust-sequoia-policy-config, rust-sequoia-sq, rust-sequoia-sqv, rust-sequoia-wot, rust-sevctl, rust-sha1collisiondetection, rust-shellcheck-sarif, rust-silver, rust-sinit, rust-skim, rust-snphost, rust-speakersafetyd, rust-ssh-key-dir, rust-system76_ectool, rust-szip, rust-tealdeer, rust-termbg, rust-tiny-dfr, rust-tokei, rust-tree-sitter-cli, rust-uefi-run, rust-uu_base32, rust-uu_base64, rust-uu_basename, rust-uu_basenc, rust-uu_cat, rust-uu_cksum, rust-uu_comm, rust-uu_cp, rust-uu_csplit, rust-uu_cut, rust-uu_date, rust-uu_dd, rust-uu_df, rust-uu_dir, rust-uu_dircolors, rust-uu_dirname, rust-uu_du, rust-uu_echo, rust-uu_env, rust-uu_expand, rust-uu_expr, rust-uu_factor, rust-uu_false, rust-uu_fmt, rust-uu_fold, rust-uu_hashsum, rust-uu_head, rust-uu_join, rust-uu_link, rust-uu_ln, rust-uu_ls, rust-uu_mkdir, rust-uu_mktemp, rust-uu_more, rust-uu_mv, rust-uu_nl, rust-uu_numfmt, rust-uu_od, rust-uu_paste, rust-uu_pr, rust-uu_printenv, rust-uu_printf, rust-uu_ptx, rust-uu_pwd, rust-uu_readlink, rust-uu_realpath, rust-uu_rm, rust-uu_rmdir, rust-uu_seq, rust-uu_shred, rust-uu_shuf, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update contains builds from a mini-mass-rebuild for Rust applications (and some C-style libraries).

Rebuilding with the Rust 1.78 toolchain should fix incomplete debug information for the Rust standard library (and the resulting low-quality stack traces). Additionally, builds will have picked up fixes for some minor low-priority security and / or safety fixes in crate dependencies that had not yet been handled via a separate (targeted) rebuild:

- h2 v0.3.26+ (denial-of-service): [link moved to references]
- glib v0.19.4+ and backports (UB): [link moved to references]
- hashbrown v0.14.5+ (UB): [link moved to references]
- rustls v0.22.4+, v0.21.11+ (denial-of-service): [link moved to references]");

  script_tag(name:"affected", value:"'glycin-loaders, gnome-tour, helix, helvum, libipuz, loupe, maturin, ntpd-rs, ruff, rust2rpm-helper, rust-add-determinism, rust-afterburn, rust-alacritty, rust-asahi-btsync, rust-asahi-nvram, rust-asahi-wifisync, rust-askalono-cli, rust-b3sum, rust-bat, rust-bindgen-cli, rust-blsctl, rust-bodhi-cli, rust-btrd, rust-cargo-deny, rust-cargo-insta, rust-cargo-readme, rust-cbindgen, rust-cfonts, rust-choosier, rust-clang-tidy-sarif, rust-clippy-sarif, rust-comrak, rust-copydeps, rust-coreos-installer, rust-count-zeroes, rust-cpc, rust-crypto-auditing-agent, rust-crypto-auditing-client, rust-crypto-auditing-event-broker, rust-crypto-auditing-log-parser, rust-desed, rust-difftastic, rust-diskonaut, rust-docopt, rust-dolby_vision, rust-dotenvy, rust-dua-cli, rust-dutree, rust-elfcat, rust-erdtree, rust-eza, rust-fd-find, rust-fedora-update-feedback, rust-gimoji, rust-git-delta, rust-gitui, rust-gst-plugin-gif, rust-gst-plugin-gtk4, rust-gst-plugin-reqwest, rust-hadolint-sarif, rust-handlebars, rust-heatseeker, rust-hexyl, rust-hyperfine, rust-ifcfg-devname, rust-is_ci, rust-jql, rust-kdotool, rust-krunvm, rust-leb128, rust-libcramjam, rust-lino, rust-local_ipaddress, rust-lscolors, rust-lsd, rust-mdsh, rust-names, rust-navi, rust-nu, rust-nu-utils, rust-oxipng, rust-pleaser, rust-pore, rust-prefixdevname, rust-pretty-bytes, rust-pretty-git-prompt, rust-procs, rust-pulldown-cmark, rust-python-launcher, rust-rav1e, rust-rbspy, rust-rd-agent, rust-rd-hashd, rust-resctl-bench, rust-resctl-demo, rust-ripgrep, rust-routinator, rust-routinator-ui, rust-rpick, rust-rpki, rust-rpm-sequoia, rust-rustcat, rust-sarif-fmt, rust-scx_layered, rust-scx_rustland, rust-scx_rusty, rust-sd, rust-sequoia-chameleon-gnupg, rust-sequoia-keyring-linter, rust-sequoia-octopus-librnp, rust-sequoia-policy-config, rust-sequoia-sq, rust-sequoia-sqv, rust-sequoia-wot, rust-sevctl, rust-sha1collisiondetection, rust-shellcheck-sarif, rust-silver, rust-sinit, rust-skim, rust-snphost, rust-speakersafetyd, rust-ssh-key-dir, rust-system76_ectool, rust-szip, rust-tealdeer, rust-termbg, rust-tiny-dfr, rust-tokei, rust-tree-sitter-cli, rust-uefi-run, rust-uu_base32, rust-uu_base64, rust-uu_basename, rust-uu_basenc, rust-uu_cat, rust-uu_cksum, rust-uu_comm, rust-uu_cp, rust-uu_csplit, rust-uu_cut, rust-uu_date, rust-uu_dd, rust-uu_df, rust-uu_dir, rust-uu_dircolors, rust-uu_dirname, rust-uu_du, rust-uu_echo, rust-uu_env, rust-uu_expand, rust-uu_expr, rust-uu_factor, rust-uu_false, rust-uu_fmt, rust-uu_fold, rust-uu_hashsum, rust-uu_head, rust-uu_join, rust-uu_link, rust-uu_ln, rust-uu_ls, rust-uu_mkdir, rust-uu_mktemp, rust-uu_more, rust-uu_mv, rust-uu_nl, rust-uu_numfmt, rust-uu_od, rust-uu_paste, rust-uu_pr, rust-uu_printenv, rust-uu_printf, rust-uu_ptx, rust-uu_pwd, rust-uu_readlink, rust-uu_realpath, rust-uu_rm, rust-uu_rmdir, rust-uu_seq, rust-uu_shred, rust-uu_shuf, rust-uu_sleep, rust-uu_sort, rust-uu_split, ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"add-determinism", rpm:"add-determinism~0.2.0~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"add-determinism-debuginfo", rpm:"add-determinism-debuginfo~0.2.0~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"add-determinism-nopython", rpm:"add-determinism-nopython~0.2.0~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"add-determinism-nopython-debuginfo", rpm:"add-determinism-nopython-debuginfo~0.2.0~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"afterburn", rpm:"afterburn~5.5.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"afterburn-debuginfo", rpm:"afterburn-debuginfo~5.5.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"afterburn-dracut", rpm:"afterburn-dracut~5.5.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"alacritty", rpm:"alacritty~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"alacritty-debuginfo", rpm:"alacritty-debuginfo~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asahi-btsync", rpm:"asahi-btsync~0.2.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asahi-btsync-debuginfo", rpm:"asahi-btsync-debuginfo~0.2.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asahi-nvram", rpm:"asahi-nvram~0.2.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asahi-nvram-debuginfo", rpm:"asahi-nvram-debuginfo~0.2.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asahi-wifisync", rpm:"asahi-wifisync~0.2.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"asahi-wifisync-debuginfo", rpm:"asahi-wifisync-debuginfo~0.2.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"askalono-cli", rpm:"askalono-cli~0.4.6~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"askalono-cli-debuginfo", rpm:"askalono-cli-debuginfo~0.4.6~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"b3sum", rpm:"b3sum~1.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"b3sum-debuginfo", rpm:"b3sum-debuginfo~1.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bat", rpm:"bat~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bat-debuginfo", rpm:"bat-debuginfo~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bindgen-cli", rpm:"bindgen-cli~0.69.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bindgen-cli-debuginfo", rpm:"bindgen-cli-debuginfo~0.69.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blsctl", rpm:"blsctl~0.2.3~14.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"blsctl-debuginfo", rpm:"blsctl-debuginfo~0.2.3~14.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bodhi-cli", rpm:"bodhi-cli~2.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bodhi-cli-debuginfo", rpm:"bodhi-cli-debuginfo~2.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btrd", rpm:"btrd~0.5.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btrd-debuginfo", rpm:"btrd-debuginfo~0.5.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"build-reproducibility-srpm-macros", rpm:"build-reproducibility-srpm-macros~0.2.0~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-deny", rpm:"cargo-deny~0.14.21~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-deny-debuginfo", rpm:"cargo-deny-debuginfo~0.14.21~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-insta", rpm:"cargo-insta~1.38.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-insta-debuginfo", rpm:"cargo-insta-debuginfo~1.38.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-readme", rpm:"cargo-readme~3.3.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-readme-debuginfo", rpm:"cargo-readme-debuginfo~3.3.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cbindgen", rpm:"cbindgen~0.26.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cbindgen-debuginfo", rpm:"cbindgen-debuginfo~0.26.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cfonts", rpm:"cfonts~1.1.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cfonts-debuginfo", rpm:"cfonts-debuginfo~1.1.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"choosier", rpm:"choosier~0.1.0~17.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"choosier-debuginfo", rpm:"choosier-debuginfo~0.1.0~17.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang-tidy-sarif", rpm:"clang-tidy-sarif~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang-tidy-sarif-debuginfo", rpm:"clang-tidy-sarif-debuginfo~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clippy-sarif", rpm:"clippy-sarif~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clippy-sarif-debuginfo", rpm:"clippy-sarif-debuginfo~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"comrak", rpm:"comrak~0.18.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"comrak-debuginfo", rpm:"comrak-debuginfo~0.18.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"copydeps", rpm:"copydeps~5.0.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"copydeps-debuginfo", rpm:"copydeps-debuginfo~5.0.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer", rpm:"coreos-installer~0.21.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-bootinfra", rpm:"coreos-installer-bootinfra~0.21.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-bootinfra-debuginfo", rpm:"coreos-installer-bootinfra-debuginfo~0.21.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-debuginfo", rpm:"coreos-installer-debuginfo~0.21.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-dracut", rpm:"coreos-installer-dracut~0.21.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"count-zeroes", rpm:"count-zeroes~0.2.1~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"count-zeroes-debuginfo", rpm:"count-zeroes-debuginfo~0.2.1~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpc", rpm:"cpc~1.9.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cpc-debuginfo", rpm:"cpc-debuginfo~1.9.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-agent", rpm:"crypto-auditing-agent~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-agent-debuginfo", rpm:"crypto-auditing-agent-debuginfo~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-client", rpm:"crypto-auditing-client~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-client-debuginfo", rpm:"crypto-auditing-client-debuginfo~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-event-broker", rpm:"crypto-auditing-event-broker~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-event-broker-debuginfo", rpm:"crypto-auditing-event-broker-debuginfo~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-log-parser", rpm:"crypto-auditing-log-parser~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-log-parser-debuginfo", rpm:"crypto-auditing-log-parser-debuginfo~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"desed", rpm:"desed~1.2.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"desed-debuginfo", rpm:"desed-debuginfo~1.2.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"difftastic", rpm:"difftastic~0.57.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"difftastic-debuginfo", rpm:"difftastic-debuginfo~0.57.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"diskonaut", rpm:"diskonaut~0.11.0~18.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"diskonaut-debuginfo", rpm:"diskonaut-debuginfo~0.11.0~18.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docopt", rpm:"docopt~1.1.1~13.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docopt-debuginfo", rpm:"docopt-debuginfo~1.1.1~13.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotenvy", rpm:"dotenvy~0.15.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotenvy-debuginfo", rpm:"dotenvy-debuginfo~0.15.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dua-cli", rpm:"dua-cli~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dua-cli-debuginfo", rpm:"dua-cli-debuginfo~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dutree", rpm:"dutree~0.2.18~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dutree-debuginfo", rpm:"dutree-debuginfo~0.2.18~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfcat", rpm:"elfcat~0.1.8~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"elfcat-debuginfo", rpm:"elfcat-debuginfo~0.1.8~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erdtree", rpm:"erdtree~3.1.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erdtree-debuginfo", rpm:"erdtree-debuginfo~3.1.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eza", rpm:"eza~0.17.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eza-debuginfo", rpm:"eza-debuginfo~0.17.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fd-find", rpm:"fd-find~9.0.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fd-find-debuginfo", rpm:"fd-find-debuginfo~9.0.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fedora-update-feedback", rpm:"fedora-update-feedback~2.1.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fedora-update-feedback-debuginfo", rpm:"fedora-update-feedback-debuginfo~2.1.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimoji", rpm:"gimoji~1.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimoji-debuginfo", rpm:"gimoji-debuginfo~1.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-delta", rpm:"git-delta~0.16.5~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-delta-debuginfo", rpm:"git-delta-debuginfo~0.16.5~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitui", rpm:"gitui~0.24.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitui-debuginfo", rpm:"gitui-debuginfo~0.24.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-loaders", rpm:"glycin-loaders~1.0.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-loaders-debuginfo", rpm:"glycin-loaders-debuginfo~1.0.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glycin-loaders-debugsource", rpm:"glycin-loaders-debugsource~1.0.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-tour", rpm:"gnome-tour~46.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-tour-debuginfo", rpm:"gnome-tour-debuginfo~46.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-tour-debugsource", rpm:"gnome-tour-debugsource~46.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-gif", rpm:"gstreamer1-plugin-gif~0.12.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-gif-debuginfo", rpm:"gstreamer1-plugin-gif-debuginfo~0.12.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-gtk4", rpm:"gstreamer1-plugin-gtk4~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-gtk4-debuginfo", rpm:"gstreamer1-plugin-gtk4-debuginfo~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-reqwest", rpm:"gstreamer1-plugin-reqwest~0.12.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-reqwest-debuginfo", rpm:"gstreamer1-plugin-reqwest-debuginfo~0.12.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hadolint-sarif", rpm:"hadolint-sarif~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hadolint-sarif-debuginfo", rpm:"hadolint-sarif-debuginfo~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"handlebars", rpm:"handlebars~5.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"handlebars-debuginfo", rpm:"handlebars-debuginfo~5.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heatseeker", rpm:"heatseeker~1.7.1~16.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"heatseeker-debuginfo", rpm:"heatseeker-debuginfo~1.7.1~16.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helix", rpm:"helix~24.03~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helix-debuginfo", rpm:"helix-debuginfo~24.03~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helix-debugsource", rpm:"helix-debugsource~24.03~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helvum", rpm:"helvum~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helvum-debuginfo", rpm:"helvum-debuginfo~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"helvum-debugsource", rpm:"helvum-debugsource~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hexyl", rpm:"hexyl~0.14.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hexyl-debuginfo", rpm:"hexyl-debuginfo~0.14.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hyperfine", rpm:"hyperfine~1.18.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hyperfine-debuginfo", rpm:"hyperfine-debuginfo~1.18.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ifcfg-devname", rpm:"ifcfg-devname~1.1.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ifcfg-devname-debuginfo", rpm:"ifcfg-devname-debuginfo~1.1.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"is_ci", rpm:"is_ci~1.2.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"is_ci-debuginfo", rpm:"is_ci-debuginfo~1.2.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jql", rpm:"jql~7.1.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"jql-debuginfo", rpm:"jql-debuginfo~7.1.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdotool", rpm:"kdotool~0.2.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdotool-debuginfo", rpm:"kdotool-debuginfo~0.2.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krunvm", rpm:"krunvm~0.1.6~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krunvm-debuginfo", rpm:"krunvm-debuginfo~0.1.6~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"leb128", rpm:"leb128~0.2.5~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"leb128-debuginfo", rpm:"leb128-debuginfo~0.2.5~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcramjam", rpm:"libcramjam~0.3.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcramjam-debuginfo", rpm:"libcramjam-debuginfo~0.3.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcramjam-devel", rpm:"libcramjam-devel~0.3.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdovi", rpm:"libdovi~3.3.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdovi-debuginfo", rpm:"libdovi-debuginfo~3.3.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdovi-devel", rpm:"libdovi-devel~3.3.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz", rpm:"libipuz~0.4.6.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz-debuginfo", rpm:"libipuz-debuginfo~0.4.6.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz-debugsource", rpm:"libipuz-debugsource~0.4.6.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz-devel", rpm:"libipuz-devel~0.4.6.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz-doc", rpm:"libipuz-doc~0.4.6.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz-tests", rpm:"libipuz-tests~0.4.6.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz-tests-debuginfo", rpm:"libipuz-tests-debuginfo~0.4.6.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lino", rpm:"lino~0.10.0~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lino-debuginfo", rpm:"lino-debuginfo~0.10.0~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"local_ipaddress", rpm:"local_ipaddress~0.1.3~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"local_ipaddress-debuginfo", rpm:"local_ipaddress-debuginfo~0.1.3~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"loupe", rpm:"loupe~46.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"loupe-debuginfo", rpm:"loupe-debuginfo~46.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"loupe-debugsource", rpm:"loupe-debugsource~46.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lscolors", rpm:"lscolors~0.17.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lscolors-debuginfo", rpm:"lscolors-debuginfo~0.17.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lsd", rpm:"lsd~1.1.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lsd-debuginfo", rpm:"lsd-debuginfo~1.1.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maturin", rpm:"maturin~1.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maturin-debuginfo", rpm:"maturin-debuginfo~1.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maturin-debugsource", rpm:"maturin-debugsource~1.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mdsh", rpm:"mdsh~0.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mdsh-debuginfo", rpm:"mdsh-debuginfo~0.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"names", rpm:"names~0.14.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"names-debuginfo", rpm:"names-debuginfo~0.14.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"navi", rpm:"navi~2.20.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"navi-debuginfo", rpm:"navi-debuginfo~2.20.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpd-rs", rpm:"ntpd-rs~1.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpd-rs-debuginfo", rpm:"ntpd-rs-debuginfo~1.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpd-rs-debugsource", rpm:"ntpd-rs-debugsource~1.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nu", rpm:"nu~0.91.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nu-debuginfo", rpm:"nu-debuginfo~0.91.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nu-utils", rpm:"nu-utils~0.91.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nu-utils-debuginfo", rpm:"nu-utils-debuginfo~0.91.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oxipng", rpm:"oxipng~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oxipng-debuginfo", rpm:"oxipng-debuginfo~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pleaser", rpm:"pleaser~0.5.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pleaser-debuginfo", rpm:"pleaser-debuginfo~0.5.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pore", rpm:"pore~0.1.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pore-debuginfo", rpm:"pore-debuginfo~0.1.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prefixdevname", rpm:"prefixdevname~0.2.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prefixdevname-debuginfo", rpm:"prefixdevname-debuginfo~0.2.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pretty-bytes", rpm:"pretty-bytes~0.2.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pretty-bytes-debuginfo", rpm:"pretty-bytes-debuginfo~0.2.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pretty-git-prompt", rpm:"pretty-git-prompt~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pretty-git-prompt-debuginfo", rpm:"pretty-git-prompt-debuginfo~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procs", rpm:"procs~0.14.4~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"procs-debuginfo", rpm:"procs-debuginfo~0.14.4~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pulldown-cmark", rpm:"pulldown-cmark~0.10.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pulldown-cmark-debuginfo", rpm:"pulldown-cmark-debuginfo~0.10.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-launcher", rpm:"python-launcher~1.0.0~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-launcher-debuginfo", rpm:"python-launcher-debuginfo~1.0.0~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rav1e", rpm:"rav1e~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rav1e-debuginfo", rpm:"rav1e-debuginfo~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rav1e-devel", rpm:"rav1e-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rav1e-libs", rpm:"rav1e-libs~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rav1e-libs-debuginfo", rpm:"rav1e-libs-debuginfo~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbspy", rpm:"rbspy~0.17.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbspy-debuginfo", rpm:"rbspy-debuginfo~0.17.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rd-agent", rpm:"rd-agent~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rd-agent-data", rpm:"rd-agent-data~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rd-agent-debuginfo", rpm:"rd-agent-debuginfo~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rd-agent-selinux", rpm:"rd-agent-selinux~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rd-hashd", rpm:"rd-hashd~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rd-hashd-debuginfo", rpm:"rd-hashd-debuginfo~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resctl-bench", rpm:"resctl-bench~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resctl-bench-debuginfo", rpm:"resctl-bench-debuginfo~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resctl-demo", rpm:"resctl-demo~2.2.5~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"resctl-demo-debuginfo", rpm:"resctl-demo-debuginfo~2.2.5~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ripgrep", rpm:"ripgrep~14.1.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ripgrep-debuginfo", rpm:"ripgrep-debuginfo~14.1.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"routinator", rpm:"routinator~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"routinator-debuginfo", rpm:"routinator-debuginfo~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"routinator-ui", rpm:"routinator-ui~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"routinator-ui-debuginfo", rpm:"routinator-ui-debuginfo~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpick", rpm:"rpick~0.9.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpick-debuginfo", rpm:"rpick-debuginfo~0.9.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpki", rpm:"rpki~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpki-debuginfo", rpm:"rpki-debuginfo~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sequoia", rpm:"rpm-sequoia~1.6.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sequoia-debuginfo", rpm:"rpm-sequoia-debuginfo~1.6.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sequoia-devel", rpm:"rpm-sequoia-devel~1.6.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff", rpm:"ruff~0.3.7~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff-debuginfo", rpm:"ruff-debuginfo~0.3.7~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff-debugsource", rpm:"ruff-debugsource~0.3.7~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-add-determinism", rpm:"rust-add-determinism~0.2.0~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-add-determinism-debuginfo", rpm:"rust-add-determinism-debuginfo~0.2.0~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-add-determinism-debugsource", rpm:"rust-add-determinism-debugsource~0.2.0~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-afterburn", rpm:"rust-afterburn~5.5.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-afterburn-debugsource", rpm:"rust-afterburn-debugsource~5.5.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-alacritty", rpm:"rust-alacritty~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-alacritty-debugsource", rpm:"rust-alacritty-debugsource~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asahi-btsync", rpm:"rust-asahi-btsync~0.2.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asahi-btsync-debugsource", rpm:"rust-asahi-btsync-debugsource~0.2.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asahi-nvram", rpm:"rust-asahi-nvram~0.2.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asahi-nvram-debugsource", rpm:"rust-asahi-nvram-debugsource~0.2.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asahi-wifisync", rpm:"rust-asahi-wifisync~0.2.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asahi-wifisync-debugsource", rpm:"rust-asahi-wifisync-debugsource~0.2.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askalono-cli", rpm:"rust-askalono-cli~0.4.6~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askalono-cli-debugsource", rpm:"rust-askalono-cli-debugsource~0.4.6~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-b3sum", rpm:"rust-b3sum~1.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-b3sum-debugsource", rpm:"rust-b3sum-debugsource~1.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+application-devel", rpm:"rust-bat+application-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+bugreport-devel", rpm:"rust-bat+bugreport-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+build-assets-devel", rpm:"rust-bat+build-assets-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+clap-devel", rpm:"rust-bat+clap-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+default-devel", rpm:"rust-bat+default-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+etcetera-devel", rpm:"rust-bat+etcetera-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+git-devel", rpm:"rust-bat+git-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+git2-devel", rpm:"rust-bat+git2-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+grep-cli-devel", rpm:"rust-bat+grep-cli-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+lessopen-devel", rpm:"rust-bat+lessopen-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+minimal-application-devel", rpm:"rust-bat+minimal-application-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+os_str_bytes-devel", rpm:"rust-bat+os_str_bytes-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+paging-devel", rpm:"rust-bat+paging-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+regex-devel", rpm:"rust-bat+regex-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+regex-fancy-devel", rpm:"rust-bat+regex-fancy-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+regex-onig-devel", rpm:"rust-bat+regex-onig-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+run_script-devel", rpm:"rust-bat+run_script-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+shell-words-devel", rpm:"rust-bat+shell-words-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+walkdir-devel", rpm:"rust-bat+walkdir-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+wild-devel", rpm:"rust-bat+wild-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat", rpm:"rust-bat~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat-debugsource", rpm:"rust-bat-debugsource~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat-devel", rpm:"rust-bat-devel~0.24.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bindgen-cli", rpm:"rust-bindgen-cli~0.69.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bindgen-cli-debugsource", rpm:"rust-bindgen-cli-debugsource~0.69.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-blsctl+default-devel", rpm:"rust-blsctl+default-devel~0.2.3~14.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-blsctl", rpm:"rust-blsctl~0.2.3~14.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-blsctl-debugsource", rpm:"rust-blsctl-debugsource~0.2.3~14.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-blsctl-devel", rpm:"rust-blsctl-devel~0.2.3~14.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bodhi-cli", rpm:"rust-bodhi-cli~2.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bodhi-cli-debugsource", rpm:"rust-bodhi-cli-debugsource~2.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-btrd+default-devel", rpm:"rust-btrd+default-devel~0.5.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-btrd", rpm:"rust-btrd~0.5.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-btrd-debugsource", rpm:"rust-btrd-debugsource~0.5.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-btrd-devel", rpm:"rust-btrd-devel~0.5.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny+default-devel", rpm:"rust-cargo-deny+default-devel~0.14.21~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny+native-certs-devel", rpm:"rust-cargo-deny+native-certs-devel~0.14.21~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny", rpm:"rust-cargo-deny~0.14.21~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny-debugsource", rpm:"rust-cargo-deny-debugsource~0.14.21~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-deny-devel", rpm:"rust-cargo-deny-devel~0.14.21~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-insta", rpm:"rust-cargo-insta~1.38.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-insta-debugsource", rpm:"rust-cargo-insta-debugsource~1.38.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-readme+default-devel", rpm:"rust-cargo-readme+default-devel~3.3.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-readme", rpm:"rust-cargo-readme~3.3.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-readme-debugsource", rpm:"rust-cargo-readme-debugsource~3.3.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-readme-devel", rpm:"rust-cargo-readme-devel~3.3.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen+clap-devel", rpm:"rust-cbindgen+clap-devel~0.26.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen+default-devel", rpm:"rust-cbindgen+default-devel~0.26.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen", rpm:"rust-cbindgen~0.26.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen-debugsource", rpm:"rust-cbindgen-debugsource~0.26.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen-devel", rpm:"rust-cbindgen-devel~0.26.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cfonts+default-devel", rpm:"rust-cfonts+default-devel~1.1.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cfonts", rpm:"rust-cfonts~1.1.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cfonts-debugsource", rpm:"rust-cfonts-debugsource~1.1.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cfonts-devel", rpm:"rust-cfonts-devel~1.1.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-choosier", rpm:"rust-choosier~0.1.0~17.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-choosier-debugsource", rpm:"rust-choosier-debugsource~0.1.0~17.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-clang-tidy-sarif", rpm:"rust-clang-tidy-sarif~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-clang-tidy-sarif-debugsource", rpm:"rust-clang-tidy-sarif-debugsource~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-clippy-sarif", rpm:"rust-clippy-sarif~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-clippy-sarif-debugsource", rpm:"rust-clippy-sarif-debugsource~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak+clap-devel", rpm:"rust-comrak+clap-devel~0.18.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak+cli-devel", rpm:"rust-comrak+cli-devel~0.18.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak+default-devel", rpm:"rust-comrak+default-devel~0.18.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak+shell-words-devel", rpm:"rust-comrak+shell-words-devel~0.18.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak+syntect-devel", rpm:"rust-comrak+syntect-devel~0.18.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak+xdg-devel", rpm:"rust-comrak+xdg-devel~0.18.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak", rpm:"rust-comrak~0.18.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak-debugsource", rpm:"rust-comrak-debugsource~0.18.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak-devel", rpm:"rust-comrak-devel~0.18.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-copydeps", rpm:"rust-copydeps~5.0.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-copydeps-debugsource", rpm:"rust-copydeps-debugsource~5.0.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer", rpm:"rust-coreos-installer~0.21.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer-debuginfo", rpm:"rust-coreos-installer-debuginfo~0.21.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer-debugsource", rpm:"rust-coreos-installer-debugsource~0.21.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-count-zeroes+default-devel", rpm:"rust-count-zeroes+default-devel~0.2.1~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-count-zeroes", rpm:"rust-count-zeroes~0.2.1~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-count-zeroes-debugsource", rpm:"rust-count-zeroes-debugsource~0.2.1~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-count-zeroes-devel", rpm:"rust-count-zeroes-devel~0.2.1~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cpc+default-devel", rpm:"rust-cpc+default-devel~1.9.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cpc", rpm:"rust-cpc~1.9.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cpc-debugsource", rpm:"rust-cpc-debugsource~1.9.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cpc-devel", rpm:"rust-cpc-devel~1.9.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-agent", rpm:"rust-crypto-auditing-agent~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-agent-debugsource", rpm:"rust-crypto-auditing-agent-debugsource~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-client", rpm:"rust-crypto-auditing-client~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-client-debugsource", rpm:"rust-crypto-auditing-client-debugsource~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-event-broker", rpm:"rust-crypto-auditing-event-broker~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-event-broker-debugsource", rpm:"rust-crypto-auditing-event-broker-debugsource~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-log-parser", rpm:"rust-crypto-auditing-log-parser~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-log-parser-debugsource", rpm:"rust-crypto-auditing-log-parser-debugsource~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-desed", rpm:"rust-desed~1.2.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-desed-debugsource", rpm:"rust-desed-debugsource~1.2.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-difftastic", rpm:"rust-difftastic~0.57.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-difftastic-debugsource", rpm:"rust-difftastic-debugsource~0.57.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-diskonaut", rpm:"rust-diskonaut~0.11.0~18.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-diskonaut-debugsource", rpm:"rust-diskonaut-debugsource~0.11.0~18.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-docopt+default-devel", rpm:"rust-docopt+default-devel~1.1.1~13.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-docopt", rpm:"rust-docopt~1.1.1~13.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-docopt-debugsource", rpm:"rust-docopt-debugsource~1.1.1~13.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-docopt-devel", rpm:"rust-docopt-devel~1.1.1~13.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dolby_vision+capi-devel", rpm:"rust-dolby_vision+capi-devel~3.3.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dolby_vision+default-devel", rpm:"rust-dolby_vision+default-devel~3.3.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dolby_vision+libc-devel", rpm:"rust-dolby_vision+libc-devel~3.3.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dolby_vision+roxmltree-devel", rpm:"rust-dolby_vision+roxmltree-devel~3.3.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dolby_vision+serde-devel", rpm:"rust-dolby_vision+serde-devel~3.3.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dolby_vision+xml-devel", rpm:"rust-dolby_vision+xml-devel~3.3.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dolby_vision", rpm:"rust-dolby_vision~3.3.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dolby_vision-debugsource", rpm:"rust-dolby_vision-debugsource~3.3.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dolby_vision-devel", rpm:"rust-dolby_vision-devel~3.3.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dotenvy+clap-devel", rpm:"rust-dotenvy+clap-devel~0.15.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dotenvy+cli-devel", rpm:"rust-dotenvy+cli-devel~0.15.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dotenvy+default-devel", rpm:"rust-dotenvy+default-devel~0.15.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dotenvy", rpm:"rust-dotenvy~0.15.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dotenvy-debugsource", rpm:"rust-dotenvy-debugsource~0.15.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dotenvy-devel", rpm:"rust-dotenvy-devel~0.15.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+crosstermion-devel", rpm:"rust-dua-cli+crosstermion-devel~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+default-devel", rpm:"rust-dua-cli+default-devel~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+open-devel", rpm:"rust-dua-cli+open-devel~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+trash-devel", rpm:"rust-dua-cli+trash-devel~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+trash-move-devel", rpm:"rust-dua-cli+trash-move-devel~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+tui-crossplatform-devel", rpm:"rust-dua-cli+tui-crossplatform-devel~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+tui-devel", rpm:"rust-dua-cli+tui-devel~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+tui-react-devel", rpm:"rust-dua-cli+tui-react-devel~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+unicode-segmentation-devel", rpm:"rust-dua-cli+unicode-segmentation-devel~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli+unicode-width-devel", rpm:"rust-dua-cli+unicode-width-devel~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli", rpm:"rust-dua-cli~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli-debugsource", rpm:"rust-dua-cli-debugsource~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dua-cli-devel", rpm:"rust-dua-cli-devel~2.29.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dutree+default-devel", rpm:"rust-dutree+default-devel~0.2.18~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dutree", rpm:"rust-dutree~0.2.18~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dutree-debugsource", rpm:"rust-dutree-debugsource~0.2.18~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-dutree-devel", rpm:"rust-dutree-devel~0.2.18~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-elfcat", rpm:"rust-elfcat~0.1.8~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-elfcat-debugsource", rpm:"rust-elfcat-debugsource~0.1.8~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-erdtree", rpm:"rust-erdtree~3.1.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-erdtree-debugsource", rpm:"rust-erdtree-debugsource~3.1.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza+default-devel", rpm:"rust-eza+default-devel~0.17.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza+git-devel", rpm:"rust-eza+git-devel~0.17.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza+git2-devel", rpm:"rust-eza+git2-devel~0.17.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza+powertest-devel", rpm:"rust-eza+powertest-devel~0.17.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza", rpm:"rust-eza~0.17.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza-debugsource", rpm:"rust-eza-debugsource~0.17.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza-devel", rpm:"rust-eza-devel~0.17.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-fd-find", rpm:"rust-fd-find~9.0.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-fd-find-debugsource", rpm:"rust-fd-find-debugsource~9.0.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-fedora-update-feedback", rpm:"rust-fedora-update-feedback~2.1.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-fedora-update-feedback-debugsource", rpm:"rust-fedora-update-feedback-debugsource~2.1.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gimoji", rpm:"rust-gimoji~1.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gimoji-debugsource", rpm:"rust-gimoji-debugsource~1.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-delta", rpm:"rust-git-delta~0.16.5~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-delta-debugsource", rpm:"rust-git-delta-debugsource~0.16.5~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gitui", rpm:"rust-gitui~0.24.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gitui-debugsource", rpm:"rust-gitui-debugsource~0.24.3~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gif+capi-devel", rpm:"rust-gst-plugin-gif+capi-devel~0.12.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gif+default-devel", rpm:"rust-gst-plugin-gif+default-devel~0.12.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gif+doc-devel", rpm:"rust-gst-plugin-gif+doc-devel~0.12.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gif+static-devel", rpm:"rust-gst-plugin-gif+static-devel~0.12.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gif", rpm:"rust-gst-plugin-gif~0.12.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gif-debugsource", rpm:"rust-gst-plugin-gif-debugsource~0.12.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gif-devel", rpm:"rust-gst-plugin-gif-devel~0.12.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+capi-devel", rpm:"rust-gst-plugin-gtk4+capi-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+default-devel", rpm:"rust-gst-plugin-gtk4+default-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+doc-devel", rpm:"rust-gst-plugin-gtk4+doc-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+gdk-wayland-devel", rpm:"rust-gst-plugin-gtk4+gdk-wayland-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+gdk-x11-devel", rpm:"rust-gst-plugin-gtk4+gdk-x11-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+gst-gl-devel", rpm:"rust-gst-plugin-gtk4+gst-gl-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+gst-gl-egl-devel", rpm:"rust-gst-plugin-gtk4+gst-gl-egl-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+gst-gl-wayland-devel", rpm:"rust-gst-plugin-gtk4+gst-gl-wayland-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+gst-gl-x11-devel", rpm:"rust-gst-plugin-gtk4+gst-gl-x11-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+gtk_v4_10-devel", rpm:"rust-gst-plugin-gtk4+gtk_v4_10-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+gtk_v4_12-devel", rpm:"rust-gst-plugin-gtk4+gtk_v4_12-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+gtk_v4_14-devel", rpm:"rust-gst-plugin-gtk4+gtk_v4_14-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+static-devel", rpm:"rust-gst-plugin-gtk4+static-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+wayland-devel", rpm:"rust-gst-plugin-gtk4+wayland-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+x11egl-devel", rpm:"rust-gst-plugin-gtk4+x11egl-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4+x11glx-devel", rpm:"rust-gst-plugin-gtk4+x11glx-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4", rpm:"rust-gst-plugin-gtk4~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4-debugsource", rpm:"rust-gst-plugin-gtk4-debugsource~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-gtk4-devel", rpm:"rust-gst-plugin-gtk4-devel~0.12.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+capi-devel", rpm:"rust-gst-plugin-reqwest+capi-devel~0.12.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+default-devel", rpm:"rust-gst-plugin-reqwest+default-devel~0.12.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+doc-devel", rpm:"rust-gst-plugin-reqwest+doc-devel~0.12.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+static-devel", rpm:"rust-gst-plugin-reqwest+static-devel~0.12.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest", rpm:"rust-gst-plugin-reqwest~0.12.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest-debugsource", rpm:"rust-gst-plugin-reqwest-debugsource~0.12.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest-devel", rpm:"rust-gst-plugin-reqwest-devel~0.12.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hadolint-sarif", rpm:"rust-hadolint-sarif~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hadolint-sarif-debugsource", rpm:"rust-hadolint-sarif-debugsource~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-handlebars+default-devel", rpm:"rust-handlebars+default-devel~5.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-handlebars+dir_source-devel", rpm:"rust-handlebars+dir_source-devel~5.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-handlebars+heck-devel", rpm:"rust-handlebars+heck-devel~5.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-handlebars+no_logging-devel", rpm:"rust-handlebars+no_logging-devel~5.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-handlebars+string_helpers-devel", rpm:"rust-handlebars+string_helpers-devel~5.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-handlebars+walkdir-devel", rpm:"rust-handlebars+walkdir-devel~5.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-handlebars", rpm:"rust-handlebars~5.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-handlebars-debugsource", rpm:"rust-handlebars-debugsource~5.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-handlebars-devel", rpm:"rust-handlebars-devel~5.1.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-heatseeker", rpm:"rust-heatseeker~1.7.1~16.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-heatseeker-debugsource", rpm:"rust-heatseeker-debugsource~1.7.1~16.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hexyl+default-devel", rpm:"rust-hexyl+default-devel~0.14.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hexyl", rpm:"rust-hexyl~0.14.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hexyl-debugsource", rpm:"rust-hexyl-debugsource~0.14.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hexyl-devel", rpm:"rust-hexyl-devel~0.14.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyperfine", rpm:"rust-hyperfine~1.18.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyperfine-debugsource", rpm:"rust-hyperfine-debugsource~1.18.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ifcfg-devname+default-devel", rpm:"rust-ifcfg-devname+default-devel~1.1.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ifcfg-devname", rpm:"rust-ifcfg-devname~1.1.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ifcfg-devname-debugsource", rpm:"rust-ifcfg-devname-debugsource~1.1.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ifcfg-devname-devel", rpm:"rust-ifcfg-devname-devel~1.1.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-is_ci+default-devel", rpm:"rust-is_ci+default-devel~1.2.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-is_ci", rpm:"rust-is_ci~1.2.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-is_ci-debugsource", rpm:"rust-is_ci-debugsource~1.2.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-is_ci-devel", rpm:"rust-is_ci-devel~1.2.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-jql", rpm:"rust-jql~7.1.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-jql-debugsource", rpm:"rust-jql-debugsource~7.1.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-kdotool", rpm:"rust-kdotool~0.2.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-kdotool-debugsource", rpm:"rust-kdotool-debugsource~0.2.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-krunvm", rpm:"rust-krunvm~0.1.6~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-krunvm-debugsource", rpm:"rust-krunvm-debugsource~0.1.6~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-leb128+default-devel", rpm:"rust-leb128+default-devel~0.2.5~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-leb128+nightly-devel", rpm:"rust-leb128+nightly-devel~0.2.5~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-leb128", rpm:"rust-leb128~0.2.5~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-leb128-debugsource", rpm:"rust-leb128-debugsource~0.2.5~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-leb128-devel", rpm:"rust-leb128-devel~0.2.5~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam+capi-devel", rpm:"rust-libcramjam+capi-devel~0.3.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam+default-devel", rpm:"rust-libcramjam+default-devel~0.3.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam+libc-devel", rpm:"rust-libcramjam+libc-devel~0.3.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam", rpm:"rust-libcramjam~0.3.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam-debugsource", rpm:"rust-libcramjam-debugsource~0.3.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam-devel", rpm:"rust-libcramjam-devel~0.3.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lino", rpm:"rust-lino~0.10.0~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lino-debugsource", rpm:"rust-lino-debugsource~0.10.0~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-local_ipaddress+default-devel", rpm:"rust-local_ipaddress+default-devel~0.1.3~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-local_ipaddress", rpm:"rust-local_ipaddress~0.1.3~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-local_ipaddress-debugsource", rpm:"rust-local_ipaddress-debugsource~0.1.3~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-local_ipaddress-devel", rpm:"rust-local_ipaddress-devel~0.1.3~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lscolors+ansi_term-devel", rpm:"rust-lscolors+ansi_term-devel~0.17.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lscolors+crossterm-devel", rpm:"rust-lscolors+crossterm-devel~0.17.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lscolors+default-devel", rpm:"rust-lscolors+default-devel~0.17.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lscolors+gnu_legacy-devel", rpm:"rust-lscolors+gnu_legacy-devel~0.17.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lscolors+nu-ansi-term-devel", rpm:"rust-lscolors+nu-ansi-term-devel~0.17.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lscolors", rpm:"rust-lscolors~0.17.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lscolors-debugsource", rpm:"rust-lscolors-debugsource~0.17.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lscolors-devel", rpm:"rust-lscolors-devel~0.17.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lsd", rpm:"rust-lsd~1.1.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lsd-debugsource", rpm:"rust-lsd-debugsource~1.1.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-mdsh", rpm:"rust-mdsh~0.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-mdsh-debugsource", rpm:"rust-mdsh-debugsource~0.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-names+application-devel", rpm:"rust-names+application-devel~0.14.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-names+clap-devel", rpm:"rust-names+clap-devel~0.14.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-names+default-devel", rpm:"rust-names+default-devel~0.14.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-names", rpm:"rust-names~0.14.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-names-debugsource", rpm:"rust-names-debugsource~0.14.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-names-devel", rpm:"rust-names-devel~0.14.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-navi+default-devel", rpm:"rust-navi+default-devel~2.20.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-navi+disable-command-execution-devel", rpm:"rust-navi+disable-command-execution-devel~2.20.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-navi+disable-repo-management-devel", rpm:"rust-navi+disable-repo-management-devel~2.20.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-navi", rpm:"rust-navi~2.20.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-navi-debugsource", rpm:"rust-navi-debugsource~2.20.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-navi-devel", rpm:"rust-navi-devel~2.20.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu", rpm:"rust-nu~0.91.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-debugsource", rpm:"rust-nu-debugsource~0.91.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-utils+default-devel", rpm:"rust-nu-utils+default-devel~0.91.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-utils", rpm:"rust-nu-utils~0.91.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-utils-debugsource", rpm:"rust-nu-utils-debugsource~0.91.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-utils-devel", rpm:"rust-nu-utils-devel~0.91.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oxipng+binary-devel", rpm:"rust-oxipng+binary-devel~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oxipng+clap-devel", rpm:"rust-oxipng+clap-devel~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oxipng+crossbeam-channel-devel", rpm:"rust-oxipng+crossbeam-channel-devel~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oxipng+default-devel", rpm:"rust-oxipng+default-devel~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oxipng+env_logger-devel", rpm:"rust-oxipng+env_logger-devel~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oxipng+filetime-devel", rpm:"rust-oxipng+filetime-devel~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oxipng+freestanding-devel", rpm:"rust-oxipng+freestanding-devel~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oxipng+parallel-devel", rpm:"rust-oxipng+parallel-devel~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oxipng+rayon-devel", rpm:"rust-oxipng+rayon-devel~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oxipng+zopfli-devel", rpm:"rust-oxipng+zopfli-devel~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oxipng", rpm:"rust-oxipng~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oxipng-debugsource", rpm:"rust-oxipng-debugsource~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oxipng-devel", rpm:"rust-oxipng-devel~9.1.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pleaser+default-devel", rpm:"rust-pleaser+default-devel~0.5.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pleaser", rpm:"rust-pleaser~0.5.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pleaser-debugsource", rpm:"rust-pleaser-debugsource~0.5.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pleaser-devel", rpm:"rust-pleaser-devel~0.5.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore+default-devel", rpm:"rust-pore+default-devel~0.1.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore", rpm:"rust-pore~0.1.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore-debugsource", rpm:"rust-pore-debugsource~0.1.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore-devel", rpm:"rust-pore-devel~0.1.11~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prefixdevname", rpm:"rust-prefixdevname~0.2.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-prefixdevname-debugsource", rpm:"rust-prefixdevname-debugsource~0.2.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pretty-bytes+default-devel", rpm:"rust-pretty-bytes+default-devel~0.2.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pretty-bytes", rpm:"rust-pretty-bytes~0.2.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pretty-bytes-debugsource", rpm:"rust-pretty-bytes-debugsource~0.2.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pretty-bytes-devel", rpm:"rust-pretty-bytes-devel~0.2.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pretty-git-prompt", rpm:"rust-pretty-git-prompt~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pretty-git-prompt-debugsource", rpm:"rust-pretty-git-prompt-debugsource~0.2.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-procs", rpm:"rust-procs~0.14.4~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-procs-debugsource", rpm:"rust-procs-debugsource~0.14.4~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pulldown-cmark+default-devel", rpm:"rust-pulldown-cmark+default-devel~0.10.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pulldown-cmark+gen-tests-devel", rpm:"rust-pulldown-cmark+gen-tests-devel~0.10.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pulldown-cmark+getopts-devel", rpm:"rust-pulldown-cmark+getopts-devel~0.10.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pulldown-cmark+html-devel", rpm:"rust-pulldown-cmark+html-devel~0.10.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pulldown-cmark+pulldown-cmark-escape-devel", rpm:"rust-pulldown-cmark+pulldown-cmark-escape-devel~0.10.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pulldown-cmark+serde-devel", rpm:"rust-pulldown-cmark+serde-devel~0.10.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pulldown-cmark+simd-devel", rpm:"rust-pulldown-cmark+simd-devel~0.10.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pulldown-cmark", rpm:"rust-pulldown-cmark~0.10.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pulldown-cmark-debugsource", rpm:"rust-pulldown-cmark-debugsource~0.10.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pulldown-cmark-devel", rpm:"rust-pulldown-cmark-devel~0.10.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-python-launcher+default-devel", rpm:"rust-python-launcher+default-devel~1.0.0~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-python-launcher", rpm:"rust-python-launcher~1.0.0~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-python-launcher-debugsource", rpm:"rust-python-launcher-debugsource~1.0.0~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-python-launcher-devel", rpm:"rust-python-launcher-devel~1.0.0~12.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+asm-devel", rpm:"rust-rav1e+asm-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+av-metrics-devel", rpm:"rust-rav1e+av-metrics-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+backtrace-devel", rpm:"rust-rav1e+backtrace-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+binaries-devel", rpm:"rust-rav1e+binaries-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+byteorder-devel", rpm:"rust-rav1e+byteorder-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+capi-devel", rpm:"rust-rav1e+capi-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+cc-devel", rpm:"rust-rav1e+cc-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+channel-api-devel", rpm:"rust-rav1e+channel-api-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+check_asm-devel", rpm:"rust-rav1e+check_asm-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+clap-devel", rpm:"rust-rav1e+clap-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+clap_complete-devel", rpm:"rust-rav1e+clap_complete-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+console-devel", rpm:"rust-rav1e+console-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+crossbeam-devel", rpm:"rust-rav1e+crossbeam-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+default-devel", rpm:"rust-rav1e+default-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+desync_finder-devel", rpm:"rust-rav1e+desync_finder-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+dump_ivf-devel", rpm:"rust-rav1e+dump_ivf-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+dump_lookahead_data-devel", rpm:"rust-rav1e+dump_lookahead_data-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+fern-devel", rpm:"rust-rav1e+fern-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+image-devel", rpm:"rust-rav1e+image-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+ivf-devel", rpm:"rust-rav1e+ivf-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+nasm-rs-devel", rpm:"rust-rav1e+nasm-rs-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+nom-devel", rpm:"rust-rav1e+nom-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+quick_test-devel", rpm:"rust-rav1e+quick_test-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+scan_fmt-devel", rpm:"rust-rav1e+scan_fmt-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+scenechange-devel", rpm:"rust-rav1e+scenechange-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+serde-big-array-devel", rpm:"rust-rav1e+serde-big-array-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+serde-devel", rpm:"rust-rav1e+serde-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+serialize-devel", rpm:"rust-rav1e+serialize-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+signal-hook-devel", rpm:"rust-rav1e+signal-hook-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+signal_support-devel", rpm:"rust-rav1e+signal_support-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+threading-devel", rpm:"rust-rav1e+threading-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+toml-devel", rpm:"rust-rav1e+toml-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+unstable-devel", rpm:"rust-rav1e+unstable-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e+y4m-devel", rpm:"rust-rav1e+y4m-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e", rpm:"rust-rav1e~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e-debuginfo", rpm:"rust-rav1e-debuginfo~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e-debugsource", rpm:"rust-rav1e-debugsource~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rav1e-devel", rpm:"rust-rav1e-devel~0.7.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rbspy+default-devel", rpm:"rust-rbspy+default-devel~0.17.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rbspy", rpm:"rust-rbspy~0.17.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rbspy-debugsource", rpm:"rust-rbspy-debugsource~0.17.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rbspy-devel", rpm:"rust-rbspy-devel~0.17.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rd-agent", rpm:"rust-rd-agent~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rd-agent-debugsource", rpm:"rust-rd-agent-debugsource~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rd-hashd", rpm:"rust-rd-hashd~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rd-hashd-debugsource", rpm:"rust-rd-hashd-debugsource~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-resctl-bench", rpm:"rust-resctl-bench~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-resctl-bench-debugsource", rpm:"rust-resctl-bench-debugsource~2.2.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-resctl-demo", rpm:"rust-resctl-demo~2.2.5~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-resctl-demo-debugsource", rpm:"rust-resctl-demo-debugsource~2.2.5~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ripgrep", rpm:"rust-ripgrep~14.1.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ripgrep-debugsource", rpm:"rust-ripgrep-debugsource~14.1.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+arbitrary-devel", rpm:"rust-routinator+arbitrary-devel~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+aspa-devel", rpm:"rust-routinator+aspa-devel~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+default-devel", rpm:"rust-routinator+default-devel~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+native-tls-devel", rpm:"rust-routinator+native-tls-devel~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+routinator-ui-devel", rpm:"rust-routinator+routinator-ui-devel~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+rta-devel", rpm:"rust-routinator+rta-devel~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+socks-devel", rpm:"rust-routinator+socks-devel~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+tls-devel", rpm:"rust-routinator+tls-devel~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+ui-devel", rpm:"rust-routinator+ui-devel~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator", rpm:"rust-routinator~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator-debugsource", rpm:"rust-routinator-debugsource~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator-devel", rpm:"rust-routinator-devel~0.13.2~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator-ui+default-devel", rpm:"rust-routinator-ui+default-devel~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator-ui", rpm:"rust-routinator-ui~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator-ui-debugsource", rpm:"rust-routinator-ui-debugsource~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator-ui-devel", rpm:"rust-routinator-ui-devel~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpick+default-devel", rpm:"rust-rpick+default-devel~0.9.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpick", rpm:"rust-rpick~0.9.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpick-debugsource", rpm:"rust-rpick-debugsource~0.9.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpick-devel", rpm:"rust-rpick-devel~0.9.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+__windows_ci_all-devel", rpm:"rust-rpki+__windows_ci_all-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+arbitrary-devel", rpm:"rust-rpki+arbitrary-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+bcder-devel", rpm:"rust-rpki+bcder-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+ca-devel", rpm:"rust-rpki+ca-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+compat-devel", rpm:"rust-rpki+compat-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+crypto-devel", rpm:"rust-rpki+crypto-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+default-devel", rpm:"rust-rpki+default-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+futures-util-devel", rpm:"rust-rpki+futures-util-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+openssl-devel", rpm:"rust-rpki+openssl-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+quick-xml-devel", rpm:"rust-rpki+quick-xml-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+repository-devel", rpm:"rust-rpki+repository-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+ring-devel", rpm:"rust-rpki+ring-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+rrdp-devel", rpm:"rust-rpki+rrdp-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+rtr-devel", rpm:"rust-rpki+rtr-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+serde-devel", rpm:"rust-rpki+serde-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+serde-support-devel", rpm:"rust-rpki+serde-support-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+serde_json-devel", rpm:"rust-rpki+serde_json-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+slurm-devel", rpm:"rust-rpki+slurm-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+softkeys-devel", rpm:"rust-rpki+softkeys-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+tokio-devel", rpm:"rust-rpki+tokio-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+tokio-stream-devel", rpm:"rust-rpki+tokio-stream-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+untrusted-devel", rpm:"rust-rpki+untrusted-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki+xml-devel", rpm:"rust-rpki+xml-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki", rpm:"rust-rpki~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki-debugsource", rpm:"rust-rpki-debugsource~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpki-devel", rpm:"rust-rpki-devel~0.18.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpm-sequoia", rpm:"rust-rpm-sequoia~1.6.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpm-sequoia-debugsource", rpm:"rust-rpm-sequoia-debugsource~1.6.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustcat", rpm:"rust-rustcat~1.3.0~11.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustcat-debugsource", rpm:"rust-rustcat-debugsource~1.3.0~11.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sarif-fmt", rpm:"rust-sarif-fmt~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sarif-fmt-debugsource", rpm:"rust-sarif-fmt-debugsource~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_layered", rpm:"rust-scx_layered~0.0.6~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_layered-debugsource", rpm:"rust-scx_layered-debugsource~0.0.6~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_rustland", rpm:"rust-scx_rustland~0.0.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_rustland-debugsource", rpm:"rust-scx_rustland-debugsource~0.0.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_rusty", rpm:"rust-scx_rusty~0.5.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-scx_rusty-debugsource", rpm:"rust-scx_rusty-debugsource~0.5.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sd", rpm:"rust-sd~1.0.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sd-debugsource", rpm:"rust-sd-debugsource~1.0.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-chameleon-gnupg", rpm:"rust-sequoia-chameleon-gnupg~0.9.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-chameleon-gnupg-debugsource", rpm:"rust-sequoia-chameleon-gnupg-debugsource~0.9.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-keyring-linter", rpm:"rust-sequoia-keyring-linter~1.0.1~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-keyring-linter-debugsource", rpm:"rust-sequoia-keyring-linter-debugsource~1.0.1~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-octopus-librnp", rpm:"rust-sequoia-octopus-librnp~1.8.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-octopus-librnp-debugsource", rpm:"rust-sequoia-octopus-librnp-debugsource~1.8.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config+crypto-nettle-devel", rpm:"rust-sequoia-policy-config+crypto-nettle-devel~0.6.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config+crypto-openssl-devel", rpm:"rust-sequoia-policy-config+crypto-openssl-devel~0.6.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config+default-devel", rpm:"rust-sequoia-policy-config+default-devel~0.6.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config", rpm:"rust-sequoia-policy-config~0.6.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config-debugsource", rpm:"rust-sequoia-policy-config-debugsource~0.6.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config-devel", rpm:"rust-sequoia-policy-config-devel~0.6.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq", rpm:"rust-sequoia-sq~0.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq-debugsource", rpm:"rust-sequoia-sq-debugsource~0.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sqv", rpm:"rust-sequoia-sqv~1.2.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sqv-debugsource", rpm:"rust-sequoia-sqv-debugsource~1.2.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot+clap-devel", rpm:"rust-sequoia-wot+clap-devel~0.11.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot+clap_complete-devel", rpm:"rust-sequoia-wot+clap_complete-devel~0.11.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot+clap_mangen-devel", rpm:"rust-sequoia-wot+clap_mangen-devel~0.11.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot+cli-devel", rpm:"rust-sequoia-wot+cli-devel~0.11.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot+crypto-nettle-devel", rpm:"rust-sequoia-wot+crypto-nettle-devel~0.11.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot+crypto-openssl-devel", rpm:"rust-sequoia-wot+crypto-openssl-devel~0.11.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot+default-devel", rpm:"rust-sequoia-wot+default-devel~0.11.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot", rpm:"rust-sequoia-wot~0.11.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot-debugsource", rpm:"rust-sequoia-wot-debugsource~0.11.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot-devel", rpm:"rust-sequoia-wot-devel~0.11.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sevctl", rpm:"rust-sevctl~0.4.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sevctl-debugsource", rpm:"rust-sevctl-debugsource~0.4.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sha1collisiondetection+clap-devel", rpm:"rust-sha1collisiondetection+clap-devel~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sha1collisiondetection+clap_mangen-devel", rpm:"rust-sha1collisiondetection+clap_mangen-devel~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sha1collisiondetection+const-oid-devel", rpm:"rust-sha1collisiondetection+const-oid-devel~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sha1collisiondetection+default-devel", rpm:"rust-sha1collisiondetection+default-devel~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sha1collisiondetection+digest-devel", rpm:"rust-sha1collisiondetection+digest-devel~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sha1collisiondetection+digest-trait-devel", rpm:"rust-sha1collisiondetection+digest-trait-devel~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sha1collisiondetection+oid-devel", rpm:"rust-sha1collisiondetection+oid-devel~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sha1collisiondetection+std-devel", rpm:"rust-sha1collisiondetection+std-devel~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sha1collisiondetection", rpm:"rust-sha1collisiondetection~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sha1collisiondetection-debugsource", rpm:"rust-sha1collisiondetection-debugsource~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sha1collisiondetection-devel", rpm:"rust-sha1collisiondetection-devel~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-shellcheck-sarif", rpm:"rust-shellcheck-sarif~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-shellcheck-sarif-debugsource", rpm:"rust-shellcheck-sarif-debugsource~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-silver", rpm:"rust-silver~2.0.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-silver-debugsource", rpm:"rust-silver-debugsource~2.0.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sinit", rpm:"rust-sinit~0.1.2~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sinit-debugsource", rpm:"rust-sinit-debugsource~0.1.2~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-skim+cli-devel", rpm:"rust-skim+cli-devel~0.10.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-skim+default-devel", rpm:"rust-skim+default-devel~0.10.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-skim", rpm:"rust-skim~0.10.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-skim-debugsource", rpm:"rust-skim-debugsource~0.10.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-skim-devel", rpm:"rust-skim-devel~0.10.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-snphost", rpm:"rust-snphost~0.1.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-snphost-debugsource", rpm:"rust-snphost-debugsource~0.1.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-speakersafetyd", rpm:"rust-speakersafetyd~0.1.9~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-speakersafetyd-debugsource", rpm:"rust-speakersafetyd-debugsource~0.1.9~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ssh-key-dir", rpm:"rust-ssh-key-dir~0.1.4~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ssh-key-dir-debugsource", rpm:"rust-ssh-key-dir-debugsource~0.1.4~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-system76_ectool+clap-devel", rpm:"rust-system76_ectool+clap-devel~0.3.8~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-system76_ectool+default-devel", rpm:"rust-system76_ectool+default-devel~0.3.8~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-system76_ectool+hidapi-devel", rpm:"rust-system76_ectool+hidapi-devel~0.3.8~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-system76_ectool+libc-devel", rpm:"rust-system76_ectool+libc-devel~0.3.8~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-system76_ectool+std-devel", rpm:"rust-system76_ectool+std-devel~0.3.8~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-system76_ectool", rpm:"rust-system76_ectool~0.3.8~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-system76_ectool-debugsource", rpm:"rust-system76_ectool-debugsource~0.3.8~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-system76_ectool-devel", rpm:"rust-system76_ectool-devel~0.3.8~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-szip", rpm:"rust-szip~1.0.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-szip-debugsource", rpm:"rust-szip-debugsource~1.0.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tealdeer", rpm:"rust-tealdeer~1.6.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tealdeer-debugsource", rpm:"rust-tealdeer-debugsource~1.6.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-termbg+default-devel", rpm:"rust-termbg+default-devel~0.4.4~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-termbg", rpm:"rust-termbg~0.4.4~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-termbg-debugsource", rpm:"rust-termbg-debugsource~0.4.4~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-termbg-devel", rpm:"rust-termbg-devel~0.4.4~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tiny-dfr", rpm:"rust-tiny-dfr~0.2.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tiny-dfr-debugsource", rpm:"rust-tiny-dfr-debugsource~0.2.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+all-devel", rpm:"rust-tokei+all-devel~12.1.2~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+cbor-devel", rpm:"rust-tokei+cbor-devel~12.1.2~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+default-devel", rpm:"rust-tokei+default-devel~12.1.2~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+hex-devel", rpm:"rust-tokei+hex-devel~12.1.2~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+serde_cbor-devel", rpm:"rust-tokei+serde_cbor-devel~12.1.2~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+serde_yaml-devel", rpm:"rust-tokei+serde_yaml-devel~12.1.2~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+yaml-devel", rpm:"rust-tokei+yaml-devel~12.1.2~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei", rpm:"rust-tokei~12.1.2~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei-debugsource", rpm:"rust-tokei-debugsource~12.1.2~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei-devel", rpm:"rust-tokei-devel~12.1.2~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tree-sitter-cli+default-devel", rpm:"rust-tree-sitter-cli+default-devel~0.22.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tree-sitter-cli", rpm:"rust-tree-sitter-cli~0.22.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tree-sitter-cli-debugsource", rpm:"rust-tree-sitter-cli-debugsource~0.22.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tree-sitter-cli-devel", rpm:"rust-tree-sitter-cli-devel~0.22.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uefi-run+default-devel", rpm:"rust-uefi-run+default-devel~0.6.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uefi-run", rpm:"rust-uefi-run~0.6.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uefi-run-debugsource", rpm:"rust-uefi-run-debugsource~0.6.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uefi-run-devel", rpm:"rust-uefi-run-devel~0.6.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_base32+default-devel", rpm:"rust-uu_base32+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_base32", rpm:"rust-uu_base32~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_base32-debugsource", rpm:"rust-uu_base32-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_base32-devel", rpm:"rust-uu_base32-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_base64+default-devel", rpm:"rust-uu_base64+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_base64", rpm:"rust-uu_base64~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_base64-debugsource", rpm:"rust-uu_base64-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_base64-devel", rpm:"rust-uu_base64-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_basename+default-devel", rpm:"rust-uu_basename+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_basename", rpm:"rust-uu_basename~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_basename-debugsource", rpm:"rust-uu_basename-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_basename-devel", rpm:"rust-uu_basename-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_basenc+default-devel", rpm:"rust-uu_basenc+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_basenc", rpm:"rust-uu_basenc~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_basenc-debugsource", rpm:"rust-uu_basenc-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_basenc-devel", rpm:"rust-uu_basenc-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cat+default-devel", rpm:"rust-uu_cat+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cat", rpm:"rust-uu_cat~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cat-debugsource", rpm:"rust-uu_cat-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cat-devel", rpm:"rust-uu_cat-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cksum+default-devel", rpm:"rust-uu_cksum+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cksum", rpm:"rust-uu_cksum~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cksum-debugsource", rpm:"rust-uu_cksum-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cksum-devel", rpm:"rust-uu_cksum-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_comm+default-devel", rpm:"rust-uu_comm+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_comm", rpm:"rust-uu_comm~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_comm-debugsource", rpm:"rust-uu_comm-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_comm-devel", rpm:"rust-uu_comm-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cp+default-devel", rpm:"rust-uu_cp+default-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cp+exacl-devel", rpm:"rust-uu_cp+exacl-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cp+feat_acl-devel", rpm:"rust-uu_cp+feat_acl-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cp+feat_selinux-devel", rpm:"rust-uu_cp+feat_selinux-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cp+selinux-devel", rpm:"rust-uu_cp+selinux-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cp", rpm:"rust-uu_cp~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cp-debugsource", rpm:"rust-uu_cp-debugsource~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cp-devel", rpm:"rust-uu_cp-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_csplit+default-devel", rpm:"rust-uu_csplit+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_csplit", rpm:"rust-uu_csplit~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_csplit-debugsource", rpm:"rust-uu_csplit-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_csplit-devel", rpm:"rust-uu_csplit-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cut+default-devel", rpm:"rust-uu_cut+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cut", rpm:"rust-uu_cut~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cut-debugsource", rpm:"rust-uu_cut-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_cut-devel", rpm:"rust-uu_cut-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_date+default-devel", rpm:"rust-uu_date+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_date", rpm:"rust-uu_date~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_date-debugsource", rpm:"rust-uu_date-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_date-devel", rpm:"rust-uu_date-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dd+default-devel", rpm:"rust-uu_dd+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dd", rpm:"rust-uu_dd~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dd-debugsource", rpm:"rust-uu_dd-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dd-devel", rpm:"rust-uu_dd-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_df+default-devel", rpm:"rust-uu_df+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_df", rpm:"rust-uu_df~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_df-debugsource", rpm:"rust-uu_df-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_df-devel", rpm:"rust-uu_df-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dir+default-devel", rpm:"rust-uu_dir+default-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dir", rpm:"rust-uu_dir~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dir-debugsource", rpm:"rust-uu_dir-debugsource~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dir-devel", rpm:"rust-uu_dir-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dircolors+default-devel", rpm:"rust-uu_dircolors+default-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dircolors", rpm:"rust-uu_dircolors~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dircolors-debugsource", rpm:"rust-uu_dircolors-debugsource~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dircolors-devel", rpm:"rust-uu_dircolors-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dirname+default-devel", rpm:"rust-uu_dirname+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dirname", rpm:"rust-uu_dirname~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dirname-debugsource", rpm:"rust-uu_dirname-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_dirname-devel", rpm:"rust-uu_dirname-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_du+default-devel", rpm:"rust-uu_du+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_du", rpm:"rust-uu_du~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_du-debugsource", rpm:"rust-uu_du-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_du-devel", rpm:"rust-uu_du-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_echo+default-devel", rpm:"rust-uu_echo+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_echo", rpm:"rust-uu_echo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_echo-debugsource", rpm:"rust-uu_echo-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_echo-devel", rpm:"rust-uu_echo-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_env+default-devel", rpm:"rust-uu_env+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_env", rpm:"rust-uu_env~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_env-debugsource", rpm:"rust-uu_env-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_env-devel", rpm:"rust-uu_env-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_expand+default-devel", rpm:"rust-uu_expand+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_expand", rpm:"rust-uu_expand~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_expand-debugsource", rpm:"rust-uu_expand-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_expand-devel", rpm:"rust-uu_expand-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_expr+default-devel", rpm:"rust-uu_expr+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_expr", rpm:"rust-uu_expr~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_expr-debugsource", rpm:"rust-uu_expr-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_expr-devel", rpm:"rust-uu_expr-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_factor+default-devel", rpm:"rust-uu_factor+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_factor", rpm:"rust-uu_factor~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_factor-debugsource", rpm:"rust-uu_factor-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_factor-devel", rpm:"rust-uu_factor-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_false+default-devel", rpm:"rust-uu_false+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_false", rpm:"rust-uu_false~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_false-debugsource", rpm:"rust-uu_false-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_false-devel", rpm:"rust-uu_false-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_fmt+default-devel", rpm:"rust-uu_fmt+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_fmt", rpm:"rust-uu_fmt~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_fmt-debugsource", rpm:"rust-uu_fmt-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_fmt-devel", rpm:"rust-uu_fmt-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_fold+default-devel", rpm:"rust-uu_fold+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_fold", rpm:"rust-uu_fold~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_fold-debugsource", rpm:"rust-uu_fold-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_fold-devel", rpm:"rust-uu_fold-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_hashsum+default-devel", rpm:"rust-uu_hashsum+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_hashsum", rpm:"rust-uu_hashsum~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_hashsum-debugsource", rpm:"rust-uu_hashsum-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_hashsum-devel", rpm:"rust-uu_hashsum-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_head+default-devel", rpm:"rust-uu_head+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_head", rpm:"rust-uu_head~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_head-debugsource", rpm:"rust-uu_head-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_head-devel", rpm:"rust-uu_head-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_join+default-devel", rpm:"rust-uu_join+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_join", rpm:"rust-uu_join~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_join-debugsource", rpm:"rust-uu_join-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_join-devel", rpm:"rust-uu_join-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_link+default-devel", rpm:"rust-uu_link+default-devel~0.0.23~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_link", rpm:"rust-uu_link~0.0.23~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_link-debugsource", rpm:"rust-uu_link-debugsource~0.0.23~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_link-devel", rpm:"rust-uu_link-devel~0.0.23~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ln+default-devel", rpm:"rust-uu_ln+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ln", rpm:"rust-uu_ln~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ln-debugsource", rpm:"rust-uu_ln-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ln-devel", rpm:"rust-uu_ln-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ls+default-devel", rpm:"rust-uu_ls+default-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ls+feat_selinux-devel", rpm:"rust-uu_ls+feat_selinux-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ls+selinux-devel", rpm:"rust-uu_ls+selinux-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ls", rpm:"rust-uu_ls~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ls-debugsource", rpm:"rust-uu_ls-debugsource~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ls-devel", rpm:"rust-uu_ls-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_mkdir+default-devel", rpm:"rust-uu_mkdir+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_mkdir", rpm:"rust-uu_mkdir~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_mkdir-debugsource", rpm:"rust-uu_mkdir-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_mkdir-devel", rpm:"rust-uu_mkdir-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_mktemp+default-devel", rpm:"rust-uu_mktemp+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_mktemp", rpm:"rust-uu_mktemp~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_mktemp-debugsource", rpm:"rust-uu_mktemp-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_mktemp-devel", rpm:"rust-uu_mktemp-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_more+default-devel", rpm:"rust-uu_more+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_more", rpm:"rust-uu_more~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_more-debugsource", rpm:"rust-uu_more-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_more-devel", rpm:"rust-uu_more-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_mv+default-devel", rpm:"rust-uu_mv+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_mv", rpm:"rust-uu_mv~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_mv-debugsource", rpm:"rust-uu_mv-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_mv-devel", rpm:"rust-uu_mv-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_nl+default-devel", rpm:"rust-uu_nl+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_nl", rpm:"rust-uu_nl~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_nl-debugsource", rpm:"rust-uu_nl-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_nl-devel", rpm:"rust-uu_nl-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_numfmt+default-devel", rpm:"rust-uu_numfmt+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_numfmt", rpm:"rust-uu_numfmt~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_numfmt-debugsource", rpm:"rust-uu_numfmt-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_numfmt-devel", rpm:"rust-uu_numfmt-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_od+default-devel", rpm:"rust-uu_od+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_od", rpm:"rust-uu_od~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_od-debugsource", rpm:"rust-uu_od-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_od-devel", rpm:"rust-uu_od-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_paste+default-devel", rpm:"rust-uu_paste+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_paste", rpm:"rust-uu_paste~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_paste-debugsource", rpm:"rust-uu_paste-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_paste-devel", rpm:"rust-uu_paste-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_pr+default-devel", rpm:"rust-uu_pr+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_pr", rpm:"rust-uu_pr~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_pr-debugsource", rpm:"rust-uu_pr-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_pr-devel", rpm:"rust-uu_pr-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_printenv+default-devel", rpm:"rust-uu_printenv+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_printenv", rpm:"rust-uu_printenv~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_printenv-debugsource", rpm:"rust-uu_printenv-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_printenv-devel", rpm:"rust-uu_printenv-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_printf+default-devel", rpm:"rust-uu_printf+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_printf", rpm:"rust-uu_printf~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_printf-debugsource", rpm:"rust-uu_printf-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_printf-devel", rpm:"rust-uu_printf-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ptx+default-devel", rpm:"rust-uu_ptx+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ptx", rpm:"rust-uu_ptx~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ptx-debugsource", rpm:"rust-uu_ptx-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_ptx-devel", rpm:"rust-uu_ptx-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_pwd+default-devel", rpm:"rust-uu_pwd+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_pwd", rpm:"rust-uu_pwd~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_pwd-debugsource", rpm:"rust-uu_pwd-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_pwd-devel", rpm:"rust-uu_pwd-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_readlink+default-devel", rpm:"rust-uu_readlink+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_readlink", rpm:"rust-uu_readlink~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_readlink-debugsource", rpm:"rust-uu_readlink-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_readlink-devel", rpm:"rust-uu_readlink-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_realpath+default-devel", rpm:"rust-uu_realpath+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_realpath", rpm:"rust-uu_realpath~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_realpath-debugsource", rpm:"rust-uu_realpath-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_realpath-devel", rpm:"rust-uu_realpath-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_rm+default-devel", rpm:"rust-uu_rm+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_rm", rpm:"rust-uu_rm~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_rm-debugsource", rpm:"rust-uu_rm-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_rm-devel", rpm:"rust-uu_rm-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_rmdir+default-devel", rpm:"rust-uu_rmdir+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_rmdir", rpm:"rust-uu_rmdir~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_rmdir-debugsource", rpm:"rust-uu_rmdir-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_rmdir-devel", rpm:"rust-uu_rmdir-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_seq+default-devel", rpm:"rust-uu_seq+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_seq", rpm:"rust-uu_seq~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_seq-debugsource", rpm:"rust-uu_seq-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_seq-devel", rpm:"rust-uu_seq-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_shred+default-devel", rpm:"rust-uu_shred+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_shred", rpm:"rust-uu_shred~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_shred-debugsource", rpm:"rust-uu_shred-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_shred-devel", rpm:"rust-uu_shred-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_shuf+default-devel", rpm:"rust-uu_shuf+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_shuf", rpm:"rust-uu_shuf~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_shuf-debugsource", rpm:"rust-uu_shuf-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_shuf-devel", rpm:"rust-uu_shuf-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_sleep+default-devel", rpm:"rust-uu_sleep+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_sleep", rpm:"rust-uu_sleep~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_sleep-debugsource", rpm:"rust-uu_sleep-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_sleep-devel", rpm:"rust-uu_sleep-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_sort+default-devel", rpm:"rust-uu_sort+default-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_sort", rpm:"rust-uu_sort~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_sort-debugsource", rpm:"rust-uu_sort-debugsource~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_sort-devel", rpm:"rust-uu_sort-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_split+default-devel", rpm:"rust-uu_split+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_split", rpm:"rust-uu_split~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_split-debugsource", rpm:"rust-uu_split-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_split-devel", rpm:"rust-uu_split-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_sum+default-devel", rpm:"rust-uu_sum+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_sum", rpm:"rust-uu_sum~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_sum-debugsource", rpm:"rust-uu_sum-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_sum-devel", rpm:"rust-uu_sum-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tac+default-devel", rpm:"rust-uu_tac+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tac", rpm:"rust-uu_tac~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tac-debugsource", rpm:"rust-uu_tac-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tac-devel", rpm:"rust-uu_tac-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tail+default-devel", rpm:"rust-uu_tail+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tail", rpm:"rust-uu_tail~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tail-debugsource", rpm:"rust-uu_tail-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tail-devel", rpm:"rust-uu_tail-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tee+default-devel", rpm:"rust-uu_tee+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tee", rpm:"rust-uu_tee~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tee-debugsource", rpm:"rust-uu_tee-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tee-devel", rpm:"rust-uu_tee-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_test+default-devel", rpm:"rust-uu_test+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_test", rpm:"rust-uu_test~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_test-debugsource", rpm:"rust-uu_test-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_test-devel", rpm:"rust-uu_test-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_touch+default-devel", rpm:"rust-uu_touch+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_touch", rpm:"rust-uu_touch~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_touch-debugsource", rpm:"rust-uu_touch-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_touch-devel", rpm:"rust-uu_touch-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tr+default-devel", rpm:"rust-uu_tr+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tr", rpm:"rust-uu_tr~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tr-debugsource", rpm:"rust-uu_tr-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tr-devel", rpm:"rust-uu_tr-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_true+default-devel", rpm:"rust-uu_true+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_true", rpm:"rust-uu_true~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_true-debugsource", rpm:"rust-uu_true-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_true-devel", rpm:"rust-uu_true-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_truncate+default-devel", rpm:"rust-uu_truncate+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_truncate", rpm:"rust-uu_truncate~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_truncate-debugsource", rpm:"rust-uu_truncate-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_truncate-devel", rpm:"rust-uu_truncate-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tsort+default-devel", rpm:"rust-uu_tsort+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tsort", rpm:"rust-uu_tsort~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tsort-debugsource", rpm:"rust-uu_tsort-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_tsort-devel", rpm:"rust-uu_tsort-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_unexpand+default-devel", rpm:"rust-uu_unexpand+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_unexpand", rpm:"rust-uu_unexpand~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_unexpand-debugsource", rpm:"rust-uu_unexpand-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_unexpand-devel", rpm:"rust-uu_unexpand-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_uniq+default-devel", rpm:"rust-uu_uniq+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_uniq", rpm:"rust-uu_uniq~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_uniq-debugsource", rpm:"rust-uu_uniq-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_uniq-devel", rpm:"rust-uu_uniq-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_unlink+default-devel", rpm:"rust-uu_unlink+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_unlink", rpm:"rust-uu_unlink~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_unlink-debugsource", rpm:"rust-uu_unlink-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_unlink-devel", rpm:"rust-uu_unlink-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_vdir+default-devel", rpm:"rust-uu_vdir+default-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_vdir", rpm:"rust-uu_vdir~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_vdir-debugsource", rpm:"rust-uu_vdir-debugsource~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_vdir-devel", rpm:"rust-uu_vdir-devel~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_wc+default-devel", rpm:"rust-uu_wc+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_wc", rpm:"rust-uu_wc~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_wc-debugsource", rpm:"rust-uu_wc-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_wc-devel", rpm:"rust-uu_wc-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_whoami+default-devel", rpm:"rust-uu_whoami+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_whoami", rpm:"rust-uu_whoami~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_whoami-debugsource", rpm:"rust-uu_whoami-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_whoami-devel", rpm:"rust-uu_whoami-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_yes+default-devel", rpm:"rust-uu_yes+default-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_yes", rpm:"rust-uu_yes~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_yes-debugsource", rpm:"rust-uu_yes-debugsource~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-uu_yes-devel", rpm:"rust-uu_yes-devel~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-varlink-cli", rpm:"rust-varlink-cli~4.5.3~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-varlink-cli-debugsource", rpm:"rust-varlink-cli-debugsource~4.5.3~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-varlink_generator+default-devel", rpm:"rust-varlink_generator+default-devel~10.1.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-varlink_generator", rpm:"rust-varlink_generator~10.1.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-varlink_generator-debugsource", rpm:"rust-varlink_generator-debugsource~10.1.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-varlink_generator-devel", rpm:"rust-varlink_generator-devel~10.1.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-device-scmi", rpm:"rust-vhost-device-scmi~0.1.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-device-scmi-debugsource", rpm:"rust-vhost-device-scmi-debugsource~0.1.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-device-sound+alsa-backend-devel", rpm:"rust-vhost-device-sound+alsa-backend-devel~0.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-device-sound+default-devel", rpm:"rust-vhost-device-sound+default-devel~0.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-device-sound+pw-backend-devel", rpm:"rust-vhost-device-sound+pw-backend-devel~0.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-device-sound+pw-devel", rpm:"rust-vhost-device-sound+pw-devel~0.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-device-sound+xen-devel", rpm:"rust-vhost-device-sound+xen-devel~0.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-device-sound", rpm:"rust-vhost-device-sound~0.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-device-sound-debugsource", rpm:"rust-vhost-device-sound-debugsource~0.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vhost-device-sound-devel", rpm:"rust-vhost-device-sound-devel~0.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl+alloc-devel", rpm:"rust-weezl+alloc-devel~0.1.8~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl+async-devel", rpm:"rust-weezl+async-devel~0.1.8~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl+default-devel", rpm:"rust-weezl+default-devel~0.1.8~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl+futures-devel", rpm:"rust-weezl+futures-devel~0.1.8~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl+std-devel", rpm:"rust-weezl+std-devel~0.1.8~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl", rpm:"rust-weezl~0.1.8~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl-debugsource", rpm:"rust-weezl-debugsource~0.1.8~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-weezl-devel", rpm:"rust-weezl-devel~0.1.8~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ybaas", rpm:"rust-ybaas~0.0.17~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ybaas-debugsource", rpm:"rust-ybaas-debugsource~0.0.17~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-yubibomb+default-devel", rpm:"rust-yubibomb+default-devel~0.2.14~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-yubibomb", rpm:"rust-yubibomb~0.2.14~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-yubibomb-debugsource", rpm:"rust-yubibomb-debugsource~0.2.14~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-yubibomb-devel", rpm:"rust-yubibomb-devel~0.2.14~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zoxide", rpm:"rust-zoxide~0.9.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zoxide-debugsource", rpm:"rust-zoxide-debugsource~0.9.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zram-generator+default-devel", rpm:"rust-zram-generator+default-devel~1.1.2~11.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zram-generator", rpm:"rust-zram-generator~1.1.2~11.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zram-generator-debugsource", rpm:"rust-zram-generator-debugsource~1.1.2~11.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zram-generator-devel", rpm:"rust-zram-generator-devel~1.1.2~11.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust2rpm-helper", rpm:"rust2rpm-helper~0.1.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust2rpm-helper-debuginfo", rpm:"rust2rpm-helper-debuginfo~0.1.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust2rpm-helper-debugsource", rpm:"rust2rpm-helper-debugsource~0.1.5~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustcat", rpm:"rustcat~1.3.0~11.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustcat-debuginfo", rpm:"rustcat-debuginfo~1.3.0~11.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustup", rpm:"rustup~1.26.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustup-debuginfo", rpm:"rustup-debuginfo~1.26.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustup-debugsource", rpm:"rustup-debugsource~1.26.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sarif-fmt", rpm:"sarif-fmt~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sarif-fmt-debuginfo", rpm:"sarif-fmt-debuginfo~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_layered", rpm:"scx_layered~0.0.6~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_layered-debuginfo", rpm:"scx_layered-debuginfo~0.0.6~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_rustland", rpm:"scx_rustland~0.0.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_rustland-debuginfo", rpm:"scx_rustland-debuginfo~0.0.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_rusty", rpm:"scx_rusty~0.5.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"scx_rusty-debuginfo", rpm:"scx_rusty-debuginfo~0.5.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sd", rpm:"sd~1.0.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sd-debuginfo", rpm:"sd-debuginfo~1.0.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-chameleon-gnupg", rpm:"sequoia-chameleon-gnupg~0.9.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-chameleon-gnupg-debuginfo", rpm:"sequoia-chameleon-gnupg-debuginfo~0.9.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-keyring-linter", rpm:"sequoia-keyring-linter~1.0.1~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-keyring-linter-debuginfo", rpm:"sequoia-keyring-linter-debuginfo~1.0.1~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-octopus-librnp", rpm:"sequoia-octopus-librnp~1.8.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-octopus-librnp-debuginfo", rpm:"sequoia-octopus-librnp-debuginfo~1.8.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-policy-config", rpm:"sequoia-policy-config~0.6.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-policy-config-debuginfo", rpm:"sequoia-policy-config-debuginfo~0.6.0~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq", rpm:"sequoia-sq~0.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq-debuginfo", rpm:"sequoia-sq-debuginfo~0.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sqv", rpm:"sequoia-sqv~1.2.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sqv-debuginfo", rpm:"sequoia-sqv-debuginfo~1.2.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-wot", rpm:"sequoia-wot~0.11.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-wot-debuginfo", rpm:"sequoia-wot-debuginfo~0.11.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sevctl", rpm:"sevctl~0.4.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sevctl-debuginfo", rpm:"sevctl-debuginfo~0.4.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sha1collisiondetection", rpm:"sha1collisiondetection~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sha1collisiondetection-debuginfo", rpm:"sha1collisiondetection-debuginfo~0.3.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shellcheck-sarif", rpm:"shellcheck-sarif~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shellcheck-sarif-debuginfo", rpm:"shellcheck-sarif-debuginfo~0.4.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"silver", rpm:"silver~2.0.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"silver-debuginfo", rpm:"silver-debuginfo~2.0.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sinit", rpm:"sinit~0.1.2~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sinit-debuginfo", rpm:"sinit-debuginfo~0.1.2~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skim", rpm:"skim~0.10.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skim-debuginfo", rpm:"skim-debuginfo~0.10.4~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snapshot", rpm:"snapshot~46.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snapshot-debuginfo", rpm:"snapshot-debuginfo~46.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snapshot-debugsource", rpm:"snapshot-debugsource~46.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snphost", rpm:"snphost~0.1.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snphost-debuginfo", rpm:"snphost-debuginfo~0.1.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"speakersafetyd", rpm:"speakersafetyd~0.1.9~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"speakersafetyd-debuginfo", rpm:"speakersafetyd-debuginfo~0.1.9~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ssh-key-dir", rpm:"ssh-key-dir~0.1.4~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ssh-key-dir-debuginfo", rpm:"ssh-key-dir-debuginfo~0.1.4~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-rs", rpm:"sudo-rs~0.2.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-rs-debuginfo", rpm:"sudo-rs-debuginfo~0.2.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-rs-debugsource", rpm:"sudo-rs-debugsource~0.2.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system76-keyboard-configurator", rpm:"system76-keyboard-configurator~1.3.10~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system76-keyboard-configurator-debuginfo", rpm:"system76-keyboard-configurator-debuginfo~1.3.10~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system76-keyboard-configurator-debugsource", rpm:"system76-keyboard-configurator-debugsource~1.3.10~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system76_ectool", rpm:"system76_ectool~0.3.8~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system76_ectool-debuginfo", rpm:"system76_ectool-debuginfo~0.3.8~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"szip", rpm:"szip~1.0.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"szip-debuginfo", rpm:"szip-debuginfo~1.0.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tealdeer", rpm:"tealdeer~1.6.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tealdeer-debuginfo", rpm:"tealdeer-debuginfo~1.6.1~8.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"termbg", rpm:"termbg~0.4.4~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"termbg-debuginfo", rpm:"termbg-debuginfo~0.4.4~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiny-dfr", rpm:"tiny-dfr~0.2.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiny-dfr-debuginfo", rpm:"tiny-dfr-debuginfo~0.2.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tokei", rpm:"tokei~12.1.2~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tokei-debuginfo", rpm:"tokei-debuginfo~12.1.2~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tree-sitter-cli", rpm:"tree-sitter-cli~0.22.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tree-sitter-cli-debuginfo", rpm:"tree-sitter-cli-debuginfo~0.22.5~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uefi-run", rpm:"uefi-run~0.6.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uefi-run-debuginfo", rpm:"uefi-run-debuginfo~0.6.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_base32", rpm:"uu_base32~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_base32-debuginfo", rpm:"uu_base32-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_base64", rpm:"uu_base64~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_base64-debuginfo", rpm:"uu_base64-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_basename", rpm:"uu_basename~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_basename-debuginfo", rpm:"uu_basename-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_basenc", rpm:"uu_basenc~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_basenc-debuginfo", rpm:"uu_basenc-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_cat", rpm:"uu_cat~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_cat-debuginfo", rpm:"uu_cat-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_cksum", rpm:"uu_cksum~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_cksum-debuginfo", rpm:"uu_cksum-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_comm", rpm:"uu_comm~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_comm-debuginfo", rpm:"uu_comm-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_cp", rpm:"uu_cp~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_cp-debuginfo", rpm:"uu_cp-debuginfo~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_csplit", rpm:"uu_csplit~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_csplit-debuginfo", rpm:"uu_csplit-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_cut", rpm:"uu_cut~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_cut-debuginfo", rpm:"uu_cut-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_date", rpm:"uu_date~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_date-debuginfo", rpm:"uu_date-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_dd", rpm:"uu_dd~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_dd-debuginfo", rpm:"uu_dd-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_df", rpm:"uu_df~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_df-debuginfo", rpm:"uu_df-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_dir", rpm:"uu_dir~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_dir-debuginfo", rpm:"uu_dir-debuginfo~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_dircolors", rpm:"uu_dircolors~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_dircolors-debuginfo", rpm:"uu_dircolors-debuginfo~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_dirname", rpm:"uu_dirname~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_dirname-debuginfo", rpm:"uu_dirname-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_du", rpm:"uu_du~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_du-debuginfo", rpm:"uu_du-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_echo", rpm:"uu_echo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_echo-debuginfo", rpm:"uu_echo-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_env", rpm:"uu_env~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_env-debuginfo", rpm:"uu_env-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_expand", rpm:"uu_expand~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_expand-debuginfo", rpm:"uu_expand-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_expr", rpm:"uu_expr~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_expr-debuginfo", rpm:"uu_expr-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_factor", rpm:"uu_factor~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_factor-debuginfo", rpm:"uu_factor-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_false", rpm:"uu_false~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_false-debuginfo", rpm:"uu_false-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_fmt", rpm:"uu_fmt~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_fmt-debuginfo", rpm:"uu_fmt-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_fold", rpm:"uu_fold~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_fold-debuginfo", rpm:"uu_fold-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_hashsum", rpm:"uu_hashsum~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_hashsum-debuginfo", rpm:"uu_hashsum-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_head", rpm:"uu_head~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_head-debuginfo", rpm:"uu_head-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_join", rpm:"uu_join~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_join-debuginfo", rpm:"uu_join-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_link", rpm:"uu_link~0.0.23~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_link-debuginfo", rpm:"uu_link-debuginfo~0.0.23~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_ln", rpm:"uu_ln~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_ln-debuginfo", rpm:"uu_ln-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_ls", rpm:"uu_ls~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_ls-debuginfo", rpm:"uu_ls-debuginfo~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_mkdir", rpm:"uu_mkdir~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_mkdir-debuginfo", rpm:"uu_mkdir-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_mktemp", rpm:"uu_mktemp~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_mktemp-debuginfo", rpm:"uu_mktemp-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_more", rpm:"uu_more~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_more-debuginfo", rpm:"uu_more-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_mv", rpm:"uu_mv~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_mv-debuginfo", rpm:"uu_mv-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_nl", rpm:"uu_nl~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_nl-debuginfo", rpm:"uu_nl-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_numfmt", rpm:"uu_numfmt~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_numfmt-debuginfo", rpm:"uu_numfmt-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_od", rpm:"uu_od~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_od-debuginfo", rpm:"uu_od-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_paste", rpm:"uu_paste~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_paste-debuginfo", rpm:"uu_paste-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_pr", rpm:"uu_pr~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_pr-debuginfo", rpm:"uu_pr-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_printenv", rpm:"uu_printenv~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_printenv-debuginfo", rpm:"uu_printenv-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_printf", rpm:"uu_printf~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_printf-debuginfo", rpm:"uu_printf-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_ptx", rpm:"uu_ptx~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_ptx-debuginfo", rpm:"uu_ptx-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_pwd", rpm:"uu_pwd~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_pwd-debuginfo", rpm:"uu_pwd-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_readlink", rpm:"uu_readlink~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_readlink-debuginfo", rpm:"uu_readlink-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_realpath", rpm:"uu_realpath~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_realpath-debuginfo", rpm:"uu_realpath-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_rm", rpm:"uu_rm~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_rm-debuginfo", rpm:"uu_rm-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_rmdir", rpm:"uu_rmdir~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_rmdir-debuginfo", rpm:"uu_rmdir-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_seq", rpm:"uu_seq~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_seq-debuginfo", rpm:"uu_seq-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_shred", rpm:"uu_shred~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_shred-debuginfo", rpm:"uu_shred-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_shuf", rpm:"uu_shuf~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_shuf-debuginfo", rpm:"uu_shuf-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_sleep", rpm:"uu_sleep~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_sleep-debuginfo", rpm:"uu_sleep-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_sort", rpm:"uu_sort~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_sort-debuginfo", rpm:"uu_sort-debuginfo~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_split", rpm:"uu_split~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_split-debuginfo", rpm:"uu_split-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_sum", rpm:"uu_sum~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_sum-debuginfo", rpm:"uu_sum-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_tac", rpm:"uu_tac~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_tac-debuginfo", rpm:"uu_tac-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_tail", rpm:"uu_tail~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_tail-debuginfo", rpm:"uu_tail-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_tee", rpm:"uu_tee~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_tee-debuginfo", rpm:"uu_tee-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_test", rpm:"uu_test~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_test-debuginfo", rpm:"uu_test-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_touch", rpm:"uu_touch~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_touch-debuginfo", rpm:"uu_touch-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_tr", rpm:"uu_tr~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_tr-debuginfo", rpm:"uu_tr-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_true", rpm:"uu_true~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_true-debuginfo", rpm:"uu_true-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_truncate", rpm:"uu_truncate~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_truncate-debuginfo", rpm:"uu_truncate-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_tsort", rpm:"uu_tsort~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_tsort-debuginfo", rpm:"uu_tsort-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_unexpand", rpm:"uu_unexpand~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_unexpand-debuginfo", rpm:"uu_unexpand-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_uniq", rpm:"uu_uniq~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_uniq-debuginfo", rpm:"uu_uniq-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_unlink", rpm:"uu_unlink~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_unlink-debuginfo", rpm:"uu_unlink-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_vdir", rpm:"uu_vdir~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_vdir-debuginfo", rpm:"uu_vdir-debuginfo~0.0.23~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_wc", rpm:"uu_wc~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_wc-debuginfo", rpm:"uu_wc-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_whoami", rpm:"uu_whoami~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_whoami-debuginfo", rpm:"uu_whoami-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_yes", rpm:"uu_yes~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uu_yes-debuginfo", rpm:"uu_yes-debuginfo~0.0.23~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"varlink-cli", rpm:"varlink-cli~4.5.3~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"varlink-cli-debuginfo", rpm:"varlink-cli-debuginfo~4.5.3~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"varlink_generator", rpm:"varlink_generator~10.1.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"varlink_generator-debuginfo", rpm:"varlink_generator-debuginfo~10.1.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhost-device-scmi", rpm:"vhost-device-scmi~0.1.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhost-device-scmi-debuginfo", rpm:"vhost-device-scmi-debuginfo~0.1.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhost-device-sound", rpm:"vhost-device-sound~0.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vhost-device-sound-debuginfo", rpm:"vhost-device-sound-debuginfo~0.1.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"weezl", rpm:"weezl~0.1.8~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"weezl-debuginfo", rpm:"weezl-debuginfo~0.1.8~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wildcard", rpm:"wildcard~0.3.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wildcard-debuginfo", rpm:"wildcard-debuginfo~0.3.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wildcard-debugsource", rpm:"wildcard-debugsource~0.3.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ybaas", rpm:"ybaas~0.0.17~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ybaas-debuginfo", rpm:"ybaas-debuginfo~0.0.17~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yubibomb", rpm:"yubibomb~0.2.14~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yubibomb-debuginfo", rpm:"yubibomb-debuginfo~0.2.14~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zoxide", rpm:"zoxide~0.9.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zoxide-debuginfo", rpm:"zoxide-debuginfo~0.9.2~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zram-generator", rpm:"zram-generator~1.1.2~11.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zram-generator-debuginfo", rpm:"zram-generator-debuginfo~1.1.2~11.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zram-generator-defaults", rpm:"zram-generator-defaults~1.1.2~11.fc41", rls:"FC41"))) {
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
