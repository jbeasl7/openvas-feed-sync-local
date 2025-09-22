# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885385");
  script_tag(name:"creation_date", value:"2023-12-06 02:14:49 +0000 (Wed, 06 Dec 2023)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2023-9790b327cb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-9790b327cb");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-9790b327cb");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2023-0044.html");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2023-0072.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clevis-pin-tpm2, keyring-ima-signer, rust-bodhi-cli, rust-coreos-installer, rust-fedora-update-feedback, rust-gst-plugin-reqwest, rust-pore, rust-rpm-sequoia, rust-sequoia-octopus-librnp, rust-sequoia-policy-config, rust-sequoia-sq, rust-sequoia-wot, rust-sevctl, rust-snphost, rust-tealdeer' package(s) announced via the FEDORA-2023-9790b327cb advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Affected applications were rebuilt against version 0.10.60 of the the `openssl` crate (the Rust bindings for OpenSSL) to address two security advisories:

- [links moved to references]");

  script_tag(name:"affected", value:"'clevis-pin-tpm2, keyring-ima-signer, rust-bodhi-cli, rust-coreos-installer, rust-fedora-update-feedback, rust-gst-plugin-reqwest, rust-pore, rust-rpm-sequoia, rust-sequoia-octopus-librnp, rust-sequoia-policy-config, rust-sequoia-sq, rust-sequoia-wot, rust-sevctl, rust-snphost, rust-tealdeer' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"bodhi-cli", rpm:"bodhi-cli~2.1.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bodhi-cli-debuginfo", rpm:"bodhi-cli-debuginfo~2.1.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clevis-pin-tpm2", rpm:"clevis-pin-tpm2~0.5.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clevis-pin-tpm2-debuginfo", rpm:"clevis-pin-tpm2-debuginfo~0.5.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clevis-pin-tpm2-debugsource", rpm:"clevis-pin-tpm2-debugsource~0.5.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer", rpm:"coreos-installer~0.18.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-bootinfra", rpm:"coreos-installer-bootinfra~0.18.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-bootinfra-debuginfo", rpm:"coreos-installer-bootinfra-debuginfo~0.18.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-debuginfo", rpm:"coreos-installer-debuginfo~0.18.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"coreos-installer-dracut", rpm:"coreos-installer-dracut~0.18.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fedora-update-feedback", rpm:"fedora-update-feedback~2.1.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fedora-update-feedback-debuginfo", rpm:"fedora-update-feedback-debuginfo~2.1.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-reqwest", rpm:"gstreamer1-plugin-reqwest~0.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1-plugin-reqwest-debuginfo", rpm:"gstreamer1-plugin-reqwest-debuginfo~0.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keyring-ima-signer", rpm:"keyring-ima-signer~0.1.0~11.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keyring-ima-signer-debuginfo", rpm:"keyring-ima-signer-debuginfo~0.1.0~11.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keyring-ima-signer-debugsource", rpm:"keyring-ima-signer-debugsource~0.1.0~11.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pore", rpm:"pore~0.1.8~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pore-debuginfo", rpm:"pore-debuginfo~0.1.8~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sequoia", rpm:"rpm-sequoia~1.5.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sequoia-debuginfo", rpm:"rpm-sequoia-debuginfo~1.5.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-sequoia-devel", rpm:"rpm-sequoia-devel~1.5.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bodhi-cli", rpm:"rust-bodhi-cli~2.1.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-bodhi-cli-debugsource", rpm:"rust-bodhi-cli-debugsource~2.1.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer", rpm:"rust-coreos-installer~0.18.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer-debuginfo", rpm:"rust-coreos-installer-debuginfo~0.18.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-coreos-installer-debugsource", rpm:"rust-coreos-installer-debugsource~0.18.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-fedora-update-feedback", rpm:"rust-fedora-update-feedback~2.1.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-fedora-update-feedback-debugsource", rpm:"rust-fedora-update-feedback-debugsource~2.1.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+capi-devel", rpm:"rust-gst-plugin-reqwest+capi-devel~0.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+default-devel", rpm:"rust-gst-plugin-reqwest+default-devel~0.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+doc-devel", rpm:"rust-gst-plugin-reqwest+doc-devel~0.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest+static-devel", rpm:"rust-gst-plugin-reqwest+static-devel~0.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest", rpm:"rust-gst-plugin-reqwest~0.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest-debugsource", rpm:"rust-gst-plugin-reqwest-debugsource~0.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gst-plugin-reqwest-devel", rpm:"rust-gst-plugin-reqwest-devel~0.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore+default-devel", rpm:"rust-pore+default-devel~0.1.8~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore", rpm:"rust-pore~0.1.8~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore-debugsource", rpm:"rust-pore-debugsource~0.1.8~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pore-devel", rpm:"rust-pore-devel~0.1.8~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpm-sequoia", rpm:"rust-rpm-sequoia~1.5.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rpm-sequoia-debugsource", rpm:"rust-rpm-sequoia-debugsource~1.5.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-octopus-librnp", rpm:"rust-sequoia-octopus-librnp~1.5.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-octopus-librnp-debugsource", rpm:"rust-sequoia-octopus-librnp-debugsource~1.5.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config+crypto-nettle-devel", rpm:"rust-sequoia-policy-config+crypto-nettle-devel~0.6.0~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config+crypto-openssl-devel", rpm:"rust-sequoia-policy-config+crypto-openssl-devel~0.6.0~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config+default-devel", rpm:"rust-sequoia-policy-config+default-devel~0.6.0~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config", rpm:"rust-sequoia-policy-config~0.6.0~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config-debugsource", rpm:"rust-sequoia-policy-config-debugsource~0.6.0~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-policy-config-devel", rpm:"rust-sequoia-policy-config-devel~0.6.0~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq", rpm:"rust-sequoia-sq~0.26.0~10.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq-debugsource", rpm:"rust-sequoia-sq-debugsource~0.26.0~10.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot+crypto-nettle-devel", rpm:"rust-sequoia-wot+crypto-nettle-devel~0.5.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot+crypto-openssl-devel", rpm:"rust-sequoia-wot+crypto-openssl-devel~0.5.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot+default-devel", rpm:"rust-sequoia-wot+default-devel~0.5.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot", rpm:"rust-sequoia-wot~0.5.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot-debugsource", rpm:"rust-sequoia-wot-debugsource~0.5.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-wot-devel", rpm:"rust-sequoia-wot-devel~0.5.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sevctl", rpm:"rust-sevctl~0.4.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sevctl-debugsource", rpm:"rust-sevctl-debugsource~0.4.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-snphost", rpm:"rust-snphost~0.1.2~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-snphost-debugsource", rpm:"rust-snphost-debugsource~0.1.2~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tealdeer", rpm:"rust-tealdeer~1.6.1~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tealdeer-debugsource", rpm:"rust-tealdeer-debugsource~1.6.1~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-octopus-librnp", rpm:"sequoia-octopus-librnp~1.5.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-octopus-librnp-debuginfo", rpm:"sequoia-octopus-librnp-debuginfo~1.5.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-policy-config", rpm:"sequoia-policy-config~0.6.0~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-policy-config-debuginfo", rpm:"sequoia-policy-config-debuginfo~0.6.0~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq", rpm:"sequoia-sq~0.26.0~10.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq-debuginfo", rpm:"sequoia-sq-debuginfo~0.26.0~10.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-wot", rpm:"sequoia-wot~0.5.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-wot-debuginfo", rpm:"sequoia-wot-debuginfo~0.5.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sevctl", rpm:"sevctl~0.4.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sevctl-debuginfo", rpm:"sevctl-debuginfo~0.4.3~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snphost", rpm:"snphost~0.1.2~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"snphost-debuginfo", rpm:"snphost-debuginfo~0.1.2~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tealdeer", rpm:"tealdeer~1.6.1~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tealdeer-debuginfo", rpm:"tealdeer-debuginfo~1.6.1~5.fc39", rls:"FC39"))) {
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
