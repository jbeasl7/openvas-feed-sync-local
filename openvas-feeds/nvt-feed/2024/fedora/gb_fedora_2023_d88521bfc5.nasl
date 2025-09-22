# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.1008852198102995");
  script_cve_id("CVE-2023-26964");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-18 18:39:51 +0000 (Tue, 18 Apr 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-d88521bfc5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-d88521bfc5");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-d88521bfc5");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2023-0005.html");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2023-0022.html");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2023-0023.html");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2023-0024.html");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2023-0034.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clevis-pin-tpm2, greetd, keyring-ima-signer, libkrun, mirrorlist-server, nispor, nmstate, rust-afterburn, rust-below, rust-bodhi-cli, rust-cargo-c, rust-coreos-installer, rust-fedora-update-feedback, rust-git-delta, rust-gst-plugin-reqwest, rust-pore, rust-rpm-sequoia, rust-sequoia-octopus-librnp, rust-sequoia-policy-config, rust-sequoia-sq, rust-sevctl, rust-tealdeer, rust-ybaas' package(s) announced via the FEDORA-2023-d88521bfc5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Recent updates for the `tokio`, `h2`, and `openssl` crates addressed some (potential or confirmed) security or soundness issues:

- `tokio`: [RUSTSEC-2023-0005]([link moved to references])
- `h2`: [RUSTSEC-2023-0034]([link moved to references]) / [CVE-2023-26964]([link moved to references])
- `openssl`: [RUSTSEC-2023-0022]([link moved to references]), [RUSTSEC-2023-0023]([link moved to references]), [RUSTSEC-2023-0024]([link moved to references])

This update contains rebuilds of all affected applications against the latest versions of these crates, which have addressed all linked issues.");

  script_tag(name:"affected", value:"'clevis-pin-tpm2, greetd, keyring-ima-signer, libkrun, mirrorlist-server, nispor, nmstate, rust-afterburn, rust-below, rust-bodhi-cli, rust-cargo-c, rust-coreos-installer, rust-fedora-update-feedback, rust-git-delta, rust-gst-plugin-reqwest, rust-pore, rust-rpm-sequoia, rust-sequoia-octopus-librnp, rust-sequoia-policy-config, rust-sequoia-sq, rust-sevctl, rust-tealdeer, rust-ybaas' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"afterburn", rpm:"afterburn~5.4.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"afterburn-debuginfo", rpm:"afterburn-debuginfo~5.4.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"afterburn-dracut", rpm:"afterburn-dracut~5.4.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"below", rpm:"below~0.6.3~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"below-debuginfo", rpm:"below-debuginfo~0.6.3~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bodhi-cli", rpm:"bodhi-cli~2.1.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bodhi-cli-debuginfo", rpm:"bodhi-cli-debuginfo~2.1.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-c", rpm:"cargo-c~0.9.12~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-c-debuginfo", rpm:"cargo-c-debuginfo~0.9.12~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clevis-pin-tpm2", rpm:"clevis-pin-tpm2~0.5.2~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clevis-pin-tpm2-debuginfo", rpm:"clevis-pin-tpm2-debuginfo~0.5.2~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clevis-pin-tpm2-debugsource", rpm:"clevis-pin-tpm2-debugsource~0.5.2~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer", rpm:"coreos-installer~0.17.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-bootinfra", rpm:"coreos-installer-bootinfra~0.17.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-bootinfra-debuginfo", rpm:"coreos-installer-bootinfra-debuginfo~0.17.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-debuginfo", rpm:"coreos-installer-debuginfo~0.17.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-dracut", rpm:"coreos-installer-dracut~0.17.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fedora-update-feedback", rpm:"fedora-update-feedback~2.1.2~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fedora-update-feedback-debuginfo", rpm:"fedora-update-feedback-debuginfo~2.1.2~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-delta", rpm:"git-delta~0.13.0~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-delta-debuginfo", rpm:"git-delta-debuginfo~0.13.0~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"greetd", rpm:"greetd~0.9.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"greetd-debuginfo", rpm:"greetd-debuginfo~0.9.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"greetd-debugsource", rpm:"greetd-debugsource~0.9.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"greetd-fakegreet", rpm:"greetd-fakegreet~0.9.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"greetd-fakegreet-debuginfo", rpm:"greetd-fakegreet-debuginfo~0.9.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"greetd-selinux", rpm:"greetd-selinux~0.9.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-reqwest", rpm:"gstreamer1-plugin-reqwest~0.10.4~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-reqwest-debuginfo", rpm:"gstreamer1-plugin-reqwest-debuginfo~0.10.4~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keyring-ima-signer", rpm:"keyring-ima-signer~0.1.0~9.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keyring-ima-signer-debuginfo", rpm:"keyring-ima-signer-debuginfo~0.1.0~9.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keyring-ima-signer-debugsource", rpm:"keyring-ima-signer-debugsource~0.1.0~9.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun", rpm:"libkrun~1.5.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-debuginfo", rpm:"libkrun-debuginfo~1.5.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-debugsource", rpm:"libkrun-debugsource~1.5.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-devel", rpm:"libkrun-devel~1.5.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-sev", rpm:"libkrun-sev~1.5.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-sev-debuginfo", rpm:"libkrun-sev-debuginfo~1.5.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-sev-devel", rpm:"libkrun-sev-devel~1.5.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mirrorlist-server", rpm:"mirrorlist-server~3.0.6~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mirrorlist-server-debuginfo", rpm:"mirrorlist-server-debuginfo~3.0.6~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mirrorlist-server-debugsource", rpm:"mirrorlist-server-debugsource~3.0.6~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nispor", rpm:"nispor~1.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nispor-debuginfo", rpm:"nispor-debuginfo~1.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nispor-debugsource", rpm:"nispor-debugsource~1.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nispor-devel", rpm:"nispor-devel~1.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nmstate", rpm:"nmstate~2.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nmstate-debuginfo", rpm:"nmstate-debuginfo~2.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nmstate-debugsource", rpm:"nmstate-debugsource~2.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nmstate-devel", rpm:"nmstate-devel~2.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nmstate-libs", rpm:"nmstate-libs~2.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nmstate-libs-debuginfo", rpm:"nmstate-libs-debuginfo~2.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nmstate-static", rpm:"nmstate-static~2.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pore", rpm:"pore~0.1.8~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pore-debuginfo", rpm:"pore-debuginfo~0.1.8~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libnmstate", rpm:"python3-libnmstate~2.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-nispor", rpm:"python3-nispor~1.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sequoia", rpm:"rpm-sequoia~1.4.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sequoia-debuginfo", rpm:"rpm-sequoia-debuginfo~1.4.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sequoia-devel", rpm:"rpm-sequoia-devel~1.4.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-afterburn", rpm:"rust-afterburn~5.4.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-afterburn-debugsource", rpm:"rust-afterburn-debugsource~5.4.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-below", rpm:"rust-below~0.6.3~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-below-debugsource", rpm:"rust-below-debugsource~0.6.3~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bodhi-cli", rpm:"rust-bodhi-cli~2.1.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bodhi-cli-debugsource", rpm:"rust-bodhi-cli-debugsource~2.1.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c+default-devel", rpm:"rust-cargo-c+default-devel~0.9.12~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c", rpm:"rust-cargo-c~0.9.12~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c-debugsource", rpm:"rust-cargo-c-debugsource~0.9.12~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c-devel", rpm:"rust-cargo-c-devel~0.9.12~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer", rpm:"rust-coreos-installer~0.17.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer-debuginfo", rpm:"rust-coreos-installer-debuginfo~0.17.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer-debugsource", rpm:"rust-coreos-installer-debugsource~0.17.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-fedora-update-feedback", rpm:"rust-fedora-update-feedback~2.1.2~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-fedora-update-feedback-debugsource", rpm:"rust-fedora-update-feedback-debugsource~2.1.2~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-delta", rpm:"rust-git-delta~0.13.0~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git-delta-debugsource", rpm:"rust-git-delta-debugsource~0.13.0~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+capi-devel", rpm:"rust-gst-plugin-reqwest+capi-devel~0.10.4~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+default-devel", rpm:"rust-gst-plugin-reqwest+default-devel~0.10.4~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+doc-devel", rpm:"rust-gst-plugin-reqwest+doc-devel~0.10.4~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+static-devel", rpm:"rust-gst-plugin-reqwest+static-devel~0.10.4~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest", rpm:"rust-gst-plugin-reqwest~0.10.4~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest-debugsource", rpm:"rust-gst-plugin-reqwest-debugsource~0.10.4~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest-devel", rpm:"rust-gst-plugin-reqwest-devel~0.10.4~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nispor+default-devel", rpm:"rust-nispor+default-devel~1.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nispor-devel", rpm:"rust-nispor-devel~1.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nmstate+default-devel", rpm:"rust-nmstate+default-devel~2.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nmstate+gen_conf-devel", rpm:"rust-nmstate+gen_conf-devel~2.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nmstate+query_apply-devel", rpm:"rust-nmstate+query_apply-devel~2.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nmstate-devel", rpm:"rust-nmstate-devel~2.2.10~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore+default-devel", rpm:"rust-pore+default-devel~0.1.8~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore", rpm:"rust-pore~0.1.8~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore-debugsource", rpm:"rust-pore-debugsource~0.1.8~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore-devel", rpm:"rust-pore-devel~0.1.8~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpm-sequoia", rpm:"rust-rpm-sequoia~1.4.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpm-sequoia-debugsource", rpm:"rust-rpm-sequoia-debugsource~1.4.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-octopus-librnp", rpm:"rust-sequoia-octopus-librnp~1.4.1~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-octopus-librnp-debugsource", rpm:"rust-sequoia-octopus-librnp-debugsource~1.4.1~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config+crypto-nettle-devel", rpm:"rust-sequoia-policy-config+crypto-nettle-devel~0.6.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config+crypto-openssl-devel", rpm:"rust-sequoia-policy-config+crypto-openssl-devel~0.6.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config+default-devel", rpm:"rust-sequoia-policy-config+default-devel~0.6.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config", rpm:"rust-sequoia-policy-config~0.6.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config-debugsource", rpm:"rust-sequoia-policy-config-debugsource~0.6.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config-devel", rpm:"rust-sequoia-policy-config-devel~0.6.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq", rpm:"rust-sequoia-sq~0.26.0~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq-debugsource", rpm:"rust-sequoia-sq-debugsource~0.26.0~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sevctl", rpm:"rust-sevctl~0.3.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sevctl-debugsource", rpm:"rust-sevctl-debugsource~0.3.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tealdeer", rpm:"rust-tealdeer~1.6.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tealdeer-debugsource", rpm:"rust-tealdeer-debugsource~1.6.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ybaas", rpm:"rust-ybaas~0.0.10~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ybaas-debugsource", rpm:"rust-ybaas-debugsource~0.0.10~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-octopus-librnp", rpm:"sequoia-octopus-librnp~1.4.1~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-octopus-librnp-debuginfo", rpm:"sequoia-octopus-librnp-debuginfo~1.4.1~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-policy-config", rpm:"sequoia-policy-config~0.6.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-policy-config-debuginfo", rpm:"sequoia-policy-config-debuginfo~0.6.0~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq", rpm:"sequoia-sq~0.26.0~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq-debuginfo", rpm:"sequoia-sq-debuginfo~0.26.0~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sevctl", rpm:"sevctl~0.3.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sevctl-debuginfo", rpm:"sevctl-debuginfo~0.3.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tealdeer", rpm:"tealdeer~1.6.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tealdeer-debuginfo", rpm:"tealdeer-debuginfo~1.6.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ybaas", rpm:"ybaas~0.0.10~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ybaas-debuginfo", rpm:"ybaas-debuginfo~0.0.10~7.fc39", rls:"FC39"))) {
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
