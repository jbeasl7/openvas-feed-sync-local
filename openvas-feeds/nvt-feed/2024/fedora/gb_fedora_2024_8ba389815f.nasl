# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885727");
  script_cve_id("CVE-2024-24575", "CVE-2024-24577");
  script_tag(name:"creation_date", value:"2024-02-20 02:03:52 +0000 (Tue, 20 Feb 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 14:54:09 +0000 (Thu, 15 Feb 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-8ba389815f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-8ba389815f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-8ba389815f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2263100");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2263105");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-asyncgit, rust-bat, rust-cargo-c, rust-eza, rust-git2, rust-git-absorb, rust-git-delta, rust-gitui, rust-libgit2-sys, rust-lsd, rust-pore, rust-pretty-git-prompt, rust-shadow-rs, rust-silver, rust-tokei, rust-vergen' package(s) announced via the FEDORA-2024-8ba389815f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update the git2 crate to version 0.18.2.
- Update the libgit2-sys crate to version 0.16.2.

Version 0.16.2 of the libgit2-sys crate includes an update of the bundled copy of libgit2 to version 1.7.2 to address CVE-2024-24575 and CVE-2024-24577.

Since the libgit2 bindings cause applications that use them to statically link libgit2, this update also includes rebuilds of all affected applications.");

  script_tag(name:"affected", value:"'rust-asyncgit, rust-bat, rust-cargo-c, rust-eza, rust-git2, rust-git-absorb, rust-git-delta, rust-gitui, rust-libgit2-sys, rust-lsd, rust-pore, rust-pretty-git-prompt, rust-shadow-rs, rust-silver, rust-tokei, rust-vergen' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"bat", rpm:"bat~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bat-debuginfo", rpm:"bat-debuginfo~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-c", rpm:"cargo-c~0.9.28~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-c-debuginfo", rpm:"cargo-c-debuginfo~0.9.28~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eza", rpm:"eza~0.17.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eza-debuginfo", rpm:"eza-debuginfo~0.17.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-absorb", rpm:"git-absorb~0.6.11~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-absorb-debuginfo", rpm:"git-absorb-debuginfo~0.6.11~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-delta", rpm:"git-delta~0.16.5~9.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-delta-debuginfo", rpm:"git-delta-debuginfo~0.16.5~9.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitui", rpm:"gitui~0.24.3~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitui-debuginfo", rpm:"gitui-debuginfo~0.24.3~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lsd", rpm:"lsd~1.0.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lsd-debuginfo", rpm:"lsd-debuginfo~1.0.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pore", rpm:"pore~0.1.10~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pore-debuginfo", rpm:"pore-debuginfo~0.1.10~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pretty-git-prompt", rpm:"pretty-git-prompt~0.2.1~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pretty-git-prompt-debuginfo", rpm:"pretty-git-prompt-debuginfo~0.2.1~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asyncgit+default-devel", rpm:"rust-asyncgit+default-devel~0.24.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asyncgit+trace-libgit-devel", rpm:"rust-asyncgit+trace-libgit-devel~0.24.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asyncgit", rpm:"rust-asyncgit~0.24.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-asyncgit-devel", rpm:"rust-asyncgit-devel~0.24.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+application-devel", rpm:"rust-bat+application-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+bugreport-devel", rpm:"rust-bat+bugreport-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+build-assets-devel", rpm:"rust-bat+build-assets-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+clap-devel", rpm:"rust-bat+clap-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+default-devel", rpm:"rust-bat+default-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+etcetera-devel", rpm:"rust-bat+etcetera-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+git-devel", rpm:"rust-bat+git-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+git2-devel", rpm:"rust-bat+git2-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+grep-cli-devel", rpm:"rust-bat+grep-cli-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+lessopen-devel", rpm:"rust-bat+lessopen-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+minimal-application-devel", rpm:"rust-bat+minimal-application-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+os_str_bytes-devel", rpm:"rust-bat+os_str_bytes-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+paging-devel", rpm:"rust-bat+paging-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+regex-devel", rpm:"rust-bat+regex-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+regex-fancy-devel", rpm:"rust-bat+regex-fancy-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+regex-onig-devel", rpm:"rust-bat+regex-onig-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+run_script-devel", rpm:"rust-bat+run_script-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+shell-words-devel", rpm:"rust-bat+shell-words-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+walkdir-devel", rpm:"rust-bat+walkdir-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat+wild-devel", rpm:"rust-bat+wild-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat", rpm:"rust-bat~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat-debugsource", rpm:"rust-bat-debugsource~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bat-devel", rpm:"rust-bat-devel~0.24.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c+default-devel", rpm:"rust-cargo-c+default-devel~0.9.28~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c", rpm:"rust-cargo-c~0.9.28~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c-debugsource", rpm:"rust-cargo-c-debugsource~0.9.28~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c-devel", rpm:"rust-cargo-c-devel~0.9.28~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza+default-devel", rpm:"rust-eza+default-devel~0.17.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza+git-devel", rpm:"rust-eza+git-devel~0.17.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza+git2-devel", rpm:"rust-eza+git2-devel~0.17.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza+powertest-devel", rpm:"rust-eza+powertest-devel~0.17.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza", rpm:"rust-eza~0.17.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza-debugsource", rpm:"rust-eza-debugsource~0.17.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eza-devel", rpm:"rust-eza-devel~0.17.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-absorb+default-devel", rpm:"rust-git-absorb+default-devel~0.6.11~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-absorb", rpm:"rust-git-absorb~0.6.11~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-absorb-debugsource", rpm:"rust-git-absorb-debugsource~0.6.11~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-absorb-devel", rpm:"rust-git-absorb-devel~0.6.11~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-delta", rpm:"rust-git-delta~0.16.5~9.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-delta-debugsource", rpm:"rust-git-delta-debugsource~0.16.5~9.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+default-devel", rpm:"rust-git2+default-devel~0.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+https-devel", rpm:"rust-git2+https-devel~0.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+openssl-probe-devel", rpm:"rust-git2+openssl-probe-devel~0.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+openssl-sys-devel", rpm:"rust-git2+openssl-sys-devel~0.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+ssh-devel", rpm:"rust-git2+ssh-devel~0.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+ssh_key_from_memory-devel", rpm:"rust-git2+ssh_key_from_memory-devel~0.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+unstable-devel", rpm:"rust-git2+unstable-devel~0.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2+vendored-libgit2-devel", rpm:"rust-git2+vendored-libgit2-devel~0.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2", rpm:"rust-git2~0.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2-devel", rpm:"rust-git2-devel~0.18.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gitui", rpm:"rust-gitui~0.24.3~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gitui-debugsource", rpm:"rust-gitui-debugsource~0.24.3~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libgit2-sys+default-devel", rpm:"rust-libgit2-sys+default-devel~0.16.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libgit2-sys+https-devel", rpm:"rust-libgit2-sys+https-devel~0.16.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libgit2-sys+libssh2-sys-devel", rpm:"rust-libgit2-sys+libssh2-sys-devel~0.16.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libgit2-sys+openssl-sys-devel", rpm:"rust-libgit2-sys+openssl-sys-devel~0.16.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libgit2-sys+ssh-devel", rpm:"rust-libgit2-sys+ssh-devel~0.16.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libgit2-sys+ssh_key_from_memory-devel", rpm:"rust-libgit2-sys+ssh_key_from_memory-devel~0.16.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libgit2-sys+vendored-devel", rpm:"rust-libgit2-sys+vendored-devel~0.16.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libgit2-sys", rpm:"rust-libgit2-sys~0.16.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libgit2-sys-devel", rpm:"rust-libgit2-sys-devel~0.16.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lsd", rpm:"rust-lsd~1.0.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lsd-debugsource", rpm:"rust-lsd-debugsource~1.0.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore+default-devel", rpm:"rust-pore+default-devel~0.1.10~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore", rpm:"rust-pore~0.1.10~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore-debugsource", rpm:"rust-pore-debugsource~0.1.10~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore-devel", rpm:"rust-pore-devel~0.1.10~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pretty-git-prompt", rpm:"rust-pretty-git-prompt~0.2.1~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pretty-git-prompt-debugsource", rpm:"rust-pretty-git-prompt-debugsource~0.2.1~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-shadow-rs+default-devel", rpm:"rust-shadow-rs+default-devel~0.8.1~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-shadow-rs+git2-devel", rpm:"rust-shadow-rs+git2-devel~0.8.1~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-shadow-rs", rpm:"rust-shadow-rs~0.8.1~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-shadow-rs-devel", rpm:"rust-shadow-rs-devel~0.8.1~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-silver", rpm:"rust-silver~2.0.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-silver-debugsource", rpm:"rust-silver-debugsource~2.0.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+all-devel", rpm:"rust-tokei+all-devel~12.1.2~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+cbor-devel", rpm:"rust-tokei+cbor-devel~12.1.2~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+default-devel", rpm:"rust-tokei+default-devel~12.1.2~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+hex-devel", rpm:"rust-tokei+hex-devel~12.1.2~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+serde_cbor-devel", rpm:"rust-tokei+serde_cbor-devel~12.1.2~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+serde_yaml-devel", rpm:"rust-tokei+serde_yaml-devel~12.1.2~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei+yaml-devel", rpm:"rust-tokei+yaml-devel~12.1.2~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei", rpm:"rust-tokei~12.1.2~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei-debugsource", rpm:"rust-tokei-debugsource~12.1.2~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokei-devel", rpm:"rust-tokei-devel~12.1.2~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+build-devel", rpm:"rust-vergen+build-devel~5.1.17~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+cargo-devel", rpm:"rust-vergen+cargo-devel~5.1.17~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+chrono-devel", rpm:"rust-vergen+chrono-devel~5.1.17~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+default-devel", rpm:"rust-vergen+default-devel~5.1.17~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+git-devel", rpm:"rust-vergen+git-devel~5.1.17~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+git2-devel", rpm:"rust-vergen+git2-devel~5.1.17~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+rustc-devel", rpm:"rust-vergen+rustc-devel~5.1.17~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+rustc_version-devel", rpm:"rust-vergen+rustc_version-devel~5.1.17~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+si-devel", rpm:"rust-vergen+si-devel~5.1.17~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen+sysinfo-devel", rpm:"rust-vergen+sysinfo-devel~5.1.17~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen", rpm:"rust-vergen~5.1.17~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-vergen-devel", rpm:"rust-vergen-devel~5.1.17~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"silver", rpm:"silver~2.0.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"silver-debuginfo", rpm:"silver-debuginfo~2.0.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tokei", rpm:"tokei~12.1.2~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tokei-debuginfo", rpm:"tokei-debuginfo~12.1.2~8.fc39", rls:"FC39"))) {
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
