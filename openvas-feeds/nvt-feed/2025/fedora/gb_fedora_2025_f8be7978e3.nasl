# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10289810179781013");
  script_cve_id("CVE-2025-0977");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-f8be7978e3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-f8be7978e3");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-f8be7978e3");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2343479");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2025-0004.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clevis-pin-tpm2, dbus-parsec, envision, fido-device-onboard, gotify-desktop, keylime-agent-rust, keyring-ima-signer, libkrun, python-cryptography, rust-afterburn, rust-cargo-vendor-filterer, rust-coreos-installer, rust-crypto-auditing-agent, rust-eif_build, rust-gst-plugin-reqwest, rust-nu, rust-oo7-cli, rust-openssl, rust-openssl-sys, rust-pore, rust-rpm-sequoia, rust-sequoia-keyring-linter, rust-sequoia-octopus-librnp, rust-sequoia-policy-config, rust-sequoia-sop, rust-sequoia-sq, rust-sequoia-sqv, rust-sevctl, rust-snphost, rust-tealdeer, rustup, s390utils' package(s) announced via the FEDORA-2025-f8be7978e3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update the openssl crate to version 0.10.70 and the openssl-sys crate to version 0.9.105.

This includes a fix for [RUSTSEC-2025-0004]([link moved to references]) / CVE-2025-0977 and rebuilds of all packages that statically link the openssl crate.");

  script_tag(name:"affected", value:"'clevis-pin-tpm2, dbus-parsec, envision, fido-device-onboard, gotify-desktop, keylime-agent-rust, keyring-ima-signer, libkrun, python-cryptography, rust-afterburn, rust-cargo-vendor-filterer, rust-coreos-installer, rust-crypto-auditing-agent, rust-eif_build, rust-gst-plugin-reqwest, rust-nu, rust-oo7-cli, rust-openssl, rust-openssl-sys, rust-pore, rust-rpm-sequoia, rust-sequoia-keyring-linter, rust-sequoia-octopus-librnp, rust-sequoia-policy-config, rust-sequoia-sop, rust-sequoia-sq, rust-sequoia-sqv, rust-sevctl, rust-snphost, rust-tealdeer, rustup, s390utils' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"afterburn", rpm:"afterburn~5.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"afterburn-debuginfo", rpm:"afterburn-debuginfo~5.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"afterburn-dracut", rpm:"afterburn-dracut~5.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-vendor-filterer", rpm:"cargo-vendor-filterer~0.5.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-vendor-filterer-debuginfo", rpm:"cargo-vendor-filterer-debuginfo~0.5.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clevis-pin-tpm2", rpm:"clevis-pin-tpm2~0.5.3~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clevis-pin-tpm2-debuginfo", rpm:"clevis-pin-tpm2-debuginfo~0.5.3~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clevis-pin-tpm2-debugsource", rpm:"clevis-pin-tpm2-debugsource~0.5.3~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer", rpm:"coreos-installer~0.23.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-bootinfra", rpm:"coreos-installer-bootinfra~0.23.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-bootinfra-debuginfo", rpm:"coreos-installer-bootinfra-debuginfo~0.23.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-debuginfo", rpm:"coreos-installer-debuginfo~0.23.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-dracut", rpm:"coreos-installer-dracut~0.23.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-agent", rpm:"crypto-auditing-agent~0.2.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crypto-auditing-agent-debuginfo", rpm:"crypto-auditing-agent-debuginfo~0.2.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-parsec", rpm:"dbus-parsec~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-parsec-debuginfo", rpm:"dbus-parsec-debuginfo~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-parsec-debugsource", rpm:"dbus-parsec-debugsource~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eif_build", rpm:"eif_build~0.2.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"eif_build-debuginfo", rpm:"eif_build-debuginfo~0.2.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"envision", rpm:"envision~2.0.0~4.20241209git2.0.0.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"envision-debuginfo", rpm:"envision-debuginfo~2.0.0~4.20241209git2.0.0.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"envision-debugsource", rpm:"envision-debugsource~2.0.0~4.20241209git2.0.0.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-admin-cli", rpm:"fdo-admin-cli~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-admin-cli-debuginfo", rpm:"fdo-admin-cli-debuginfo~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-client", rpm:"fdo-client~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-client-debuginfo", rpm:"fdo-client-debuginfo~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-init", rpm:"fdo-init~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-init-debuginfo", rpm:"fdo-init-debuginfo~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-manufacturing-server", rpm:"fdo-manufacturing-server~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-manufacturing-server-debuginfo", rpm:"fdo-manufacturing-server-debuginfo~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-owner-cli", rpm:"fdo-owner-cli~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-owner-cli-debuginfo", rpm:"fdo-owner-cli-debuginfo~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-owner-onboarding-server", rpm:"fdo-owner-onboarding-server~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-owner-onboarding-server-debuginfo", rpm:"fdo-owner-onboarding-server-debuginfo~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-rendezvous-server", rpm:"fdo-rendezvous-server~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fdo-rendezvous-server-debuginfo", rpm:"fdo-rendezvous-server-debuginfo~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fido-device-onboard", rpm:"fido-device-onboard~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fido-device-onboard-debuginfo", rpm:"fido-device-onboard-debuginfo~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fido-device-onboard-debugsource", rpm:"fido-device-onboard-debugsource~0.5.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gotify-desktop", rpm:"gotify-desktop~1.3.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gotify-desktop-debuginfo", rpm:"gotify-desktop-debuginfo~1.3.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gotify-desktop-debugsource", rpm:"gotify-desktop-debugsource~1.3.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-reqwest", rpm:"gstreamer1-plugin-reqwest~0.13.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-reqwest-debuginfo", rpm:"gstreamer1-plugin-reqwest-debuginfo~0.13.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust", rpm:"keylime-agent-rust~0.2.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-debuginfo", rpm:"keylime-agent-rust-debuginfo~0.2.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-agent-rust-debugsource", rpm:"keylime-agent-rust-debugsource~0.2.7~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keyring-ima-signer", rpm:"keyring-ima-signer~0.1.0~17.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keyring-ima-signer-debuginfo", rpm:"keyring-ima-signer-debuginfo~0.1.0~17.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keyring-ima-signer-debugsource", rpm:"keyring-ima-signer-debugsource~0.1.0~17.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun", rpm:"libkrun~1.10.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-debuginfo", rpm:"libkrun-debuginfo~1.10.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-debugsource", rpm:"libkrun-debugsource~1.10.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-devel", rpm:"libkrun-devel~1.10.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-sev", rpm:"libkrun-sev~1.10.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-sev-debuginfo", rpm:"libkrun-sev-debuginfo~1.10.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrun-sev-devel", rpm:"libkrun-sev-devel~1.10.1~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nu", rpm:"nu~0.99.1~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nu-debuginfo", rpm:"nu-debuginfo~0.99.1~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oo7-cli", rpm:"oo7-cli~0.3.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oo7-cli-debuginfo", rpm:"oo7-cli-debuginfo~0.3.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pore", rpm:"pore~0.1.17~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pore-debuginfo", rpm:"pore-debuginfo~0.1.17~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography", rpm:"python-cryptography~43.0.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography-debugsource", rpm:"python-cryptography-debugsource~43.0.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography", rpm:"python3-cryptography~43.0.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography-debuginfo", rpm:"python3-cryptography-debuginfo~43.0.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sequoia", rpm:"rpm-sequoia~1.7.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sequoia-debuginfo", rpm:"rpm-sequoia-debuginfo~1.7.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sequoia-devel", rpm:"rpm-sequoia-devel~1.7.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-afterburn", rpm:"rust-afterburn~5.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-afterburn-debugsource", rpm:"rust-afterburn-debugsource~5.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-vendor-filterer+default-devel", rpm:"rust-cargo-vendor-filterer+default-devel~0.5.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-vendor-filterer", rpm:"rust-cargo-vendor-filterer~0.5.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-vendor-filterer-debugsource", rpm:"rust-cargo-vendor-filterer-debugsource~0.5.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-vendor-filterer-devel", rpm:"rust-cargo-vendor-filterer-devel~0.5.17~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer", rpm:"rust-coreos-installer~0.23.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer-debuginfo", rpm:"rust-coreos-installer-debuginfo~0.23.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer-debugsource", rpm:"rust-coreos-installer-debugsource~0.23.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-agent", rpm:"rust-crypto-auditing-agent~0.2.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crypto-auditing-agent-debugsource", rpm:"rust-crypto-auditing-agent-debugsource~0.2.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eif_build", rpm:"rust-eif_build~0.2.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-eif_build-debugsource", rpm:"rust-eif_build-debugsource~0.2.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+capi-devel", rpm:"rust-gst-plugin-reqwest+capi-devel~0.13.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+default-devel", rpm:"rust-gst-plugin-reqwest+default-devel~0.13.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+doc-devel", rpm:"rust-gst-plugin-reqwest+doc-devel~0.13.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+static-devel", rpm:"rust-gst-plugin-reqwest+static-devel~0.13.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest", rpm:"rust-gst-plugin-reqwest~0.13.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest-debugsource", rpm:"rust-gst-plugin-reqwest-debugsource~0.13.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest-devel", rpm:"rust-gst-plugin-reqwest-devel~0.13.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu", rpm:"rust-nu~0.99.1~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-debugsource", rpm:"rust-nu-debugsource~0.99.1~7.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oo7-cli", rpm:"rust-oo7-cli~0.3.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-oo7-cli-debugsource", rpm:"rust-oo7-cli-debugsource~0.3.3~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl+bindgen-devel", rpm:"rust-openssl+bindgen-devel~0.10.70~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl+default-devel", rpm:"rust-openssl+default-devel~0.10.70~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl+v101-devel", rpm:"rust-openssl+v101-devel~0.10.70~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl+v102-devel", rpm:"rust-openssl+v102-devel~0.10.70~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl+v110-devel", rpm:"rust-openssl+v110-devel~0.10.70~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl+v111-devel", rpm:"rust-openssl+v111-devel~0.10.70~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl", rpm:"rust-openssl~0.10.70~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl-devel", rpm:"rust-openssl-devel~0.10.70~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl-sys+bindgen-devel", rpm:"rust-openssl-sys+bindgen-devel~0.9.105~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl-sys+default-devel", rpm:"rust-openssl-sys+default-devel~0.9.105~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl-sys", rpm:"rust-openssl-sys~0.9.105~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl-sys-devel", rpm:"rust-openssl-sys-devel~0.9.105~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore+default-devel", rpm:"rust-pore+default-devel~0.1.17~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore", rpm:"rust-pore~0.1.17~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore-debugsource", rpm:"rust-pore-debugsource~0.1.17~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore-devel", rpm:"rust-pore-devel~0.1.17~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpm-sequoia", rpm:"rust-rpm-sequoia~1.7.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpm-sequoia-debugsource", rpm:"rust-rpm-sequoia-debugsource~1.7.0~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-keyring-linter", rpm:"rust-sequoia-keyring-linter~1.0.1~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-keyring-linter-debugsource", rpm:"rust-sequoia-keyring-linter-debugsource~1.0.1~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-octopus-librnp", rpm:"rust-sequoia-octopus-librnp~1.10.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-octopus-librnp-debugsource", rpm:"rust-sequoia-octopus-librnp-debugsource~1.10.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config+crypto-nettle-devel", rpm:"rust-sequoia-policy-config+crypto-nettle-devel~0.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config+crypto-openssl-devel", rpm:"rust-sequoia-policy-config+crypto-openssl-devel~0.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config+crypto-rust-devel", rpm:"rust-sequoia-policy-config+crypto-rust-devel~0.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config+default-devel", rpm:"rust-sequoia-policy-config+default-devel~0.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config", rpm:"rust-sequoia-policy-config~0.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config-debugsource", rpm:"rust-sequoia-policy-config-debugsource~0.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config-devel", rpm:"rust-sequoia-policy-config-devel~0.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sop+cli-devel", rpm:"rust-sequoia-sop+cli-devel~0.36.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sop+cliv-devel", rpm:"rust-sequoia-sop+cliv-devel~0.36.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sop+crypto-nettle-devel", rpm:"rust-sequoia-sop+crypto-nettle-devel~0.36.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sop+crypto-openssl-devel", rpm:"rust-sequoia-sop+crypto-openssl-devel~0.36.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sop+crypto-rust-devel", rpm:"rust-sequoia-sop+crypto-rust-devel~0.36.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sop+default-devel", rpm:"rust-sequoia-sop+default-devel~0.36.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sop", rpm:"rust-sequoia-sop~0.36.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sop-debugsource", rpm:"rust-sequoia-sop-debugsource~0.36.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sop-devel", rpm:"rust-sequoia-sop-devel~0.36.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq", rpm:"rust-sequoia-sq~1.1.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq-debugsource", rpm:"rust-sequoia-sq-debugsource~1.1.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sqv", rpm:"rust-sequoia-sqv~1.2.1~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sqv-debugsource", rpm:"rust-sequoia-sqv-debugsource~1.2.1~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sevctl", rpm:"rust-sevctl~0.6.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sevctl-debugsource", rpm:"rust-sevctl-debugsource~0.6.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-snphost", rpm:"rust-snphost~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-snphost-debugsource", rpm:"rust-snphost-debugsource~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tealdeer", rpm:"rust-tealdeer~1.7.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tealdeer-debugsource", rpm:"rust-tealdeer-debugsource~1.7.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustup", rpm:"rustup~1.27.1~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustup-debuginfo", rpm:"rustup-debuginfo~1.27.1~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustup-debugsource", rpm:"rustup-debugsource~1.27.1~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils", rpm:"s390utils~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-base", rpm:"s390utils-base~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-base-debuginfo", rpm:"s390utils-base-debuginfo~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-chreipl-fcp-mpath", rpm:"s390utils-chreipl-fcp-mpath~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-cmsfs-fuse", rpm:"s390utils-cmsfs-fuse~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-cmsfs-fuse-debuginfo", rpm:"s390utils-cmsfs-fuse-debuginfo~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-core", rpm:"s390utils-core~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-core-debuginfo", rpm:"s390utils-core-debuginfo~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-cpacfstatsd", rpm:"s390utils-cpacfstatsd~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-cpacfstatsd-debuginfo", rpm:"s390utils-cpacfstatsd-debuginfo~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-cpuplugd", rpm:"s390utils-cpuplugd~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-cpuplugd-debuginfo", rpm:"s390utils-cpuplugd-debuginfo~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-debuginfo", rpm:"s390utils-debuginfo~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-debugsource", rpm:"s390utils-debugsource~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-devel", rpm:"s390utils-devel~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-hmcdrvfs", rpm:"s390utils-hmcdrvfs~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-hmcdrvfs-debuginfo", rpm:"s390utils-hmcdrvfs-debuginfo~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-iucvterm", rpm:"s390utils-iucvterm~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-iucvterm-debuginfo", rpm:"s390utils-iucvterm-debuginfo~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-mon_statd", rpm:"s390utils-mon_statd~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-mon_statd-debuginfo", rpm:"s390utils-mon_statd-debuginfo~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-osasnmpd", rpm:"s390utils-osasnmpd~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-osasnmpd-debuginfo", rpm:"s390utils-osasnmpd-debuginfo~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-se-data", rpm:"s390utils-se-data~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-zdsfs", rpm:"s390utils-zdsfs~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-zdsfs-debuginfo", rpm:"s390utils-zdsfs-debuginfo~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-ziomon", rpm:"s390utils-ziomon~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"s390utils-ziomon-debuginfo", rpm:"s390utils-ziomon-debuginfo~2.35.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-keyring-linter", rpm:"sequoia-keyring-linter~1.0.1~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-keyring-linter-debuginfo", rpm:"sequoia-keyring-linter-debuginfo~1.0.1~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-octopus-librnp", rpm:"sequoia-octopus-librnp~1.10.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-octopus-librnp-debuginfo", rpm:"sequoia-octopus-librnp-debuginfo~1.10.0~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-policy-config", rpm:"sequoia-policy-config~0.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-policy-config-debuginfo", rpm:"sequoia-policy-config-debuginfo~0.7.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sop", rpm:"sequoia-sop~0.36.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sop-debuginfo", rpm:"sequoia-sop-debuginfo~0.36.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq", rpm:"sequoia-sq~1.1.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq-debuginfo", rpm:"sequoia-sq-debuginfo~1.1.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sqv", rpm:"sequoia-sqv~1.2.1~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sqv-debuginfo", rpm:"sequoia-sqv-debuginfo~1.2.1~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sevctl", rpm:"sevctl~0.6.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sevctl-debuginfo", rpm:"sevctl-debuginfo~0.6.0~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snphost", rpm:"snphost~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snphost-debuginfo", rpm:"snphost-debuginfo~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tealdeer", rpm:"tealdeer~1.7.1~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tealdeer-debuginfo", rpm:"tealdeer-debuginfo~1.7.1~3.fc41", rls:"FC41"))) {
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
