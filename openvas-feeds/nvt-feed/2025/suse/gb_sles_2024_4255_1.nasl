# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.4255.1");
  script_cve_id("CVE-2023-31315");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:4255-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4255-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244255-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234027");
  script_xref(name:"URL", value:"https://git.codelinaro.org/clo/ath-firmware/ath12k-firmware");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-December/019965.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware' package(s) announced via the SUSE-SU-2024:4255-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:

- Update to version 20241128 (git commit ea71da6f0690):
 * i915: Update Xe2LPD DMC to v2.24
 * cirrus: cs35l56: Add firmware for Cirrus CS35L56 for various Dell laptops
 * iwlwifi: add Bz-gf FW for core89-91 release
 * amdgpu: update smu 13.0.10 firmware
 * amdgpu: update sdma 6.0.3 firmware
 * amdgpu: update psp 13.0.10 firmware
 * amdgpu: update gc 11.0.3 firmware
 * amdgpu: add smu 13.0.14 firmware
 * amdgpu: add sdma 4.4.5 firmware
 * amdgpu: add psp 13.0.14 firmware
 * amdgpu: add gc 9.4.4 firmware
 * amdgpu: update vcn 3.1.2 firmware
 * amdgpu: update psp 13.0.5 firmware
 * amdgpu: update psp 13.0.8 firmware
 * amdgpu: update vega20 firmware
 * amdgpu: update vega12 firmware
 * amdgpu: update psp 14.0.4 firmware
 * amdgpu: update gc 11.5.2 firmware
 * amdgpu: update vega10 firmware
 * amdgpu: update vcn 4.0.0 firmware
 * amdgpu: update smu 13.0.0 firmware
 * amdgpu: update psp 13.0.0 firmware
 * amdgpu: update gc 11.0.0 firmware
 * amdgpu: update beige goby firmware
 * amdgpu: update vangogh firmware
 * amdgpu: update dimgrey cavefish firmware
 * amdgpu: update navy flounder firmware
 * amdgpu: update psp 13.0.11 firmware
 * amdgpu: update gc 11.0.4 firmware
 * amdgpu: update vcn 4.0.2 firmware
 * amdgpu: update psp 13.0.4 firmware
 * amdgpu: update gc 11.0.1 firmware
 * amdgpu: update sienna cichlid firmware
 * amdgpu: update vpe 6.1.1 firmware
 * amdgpu: update vcn 4.0.6 firmware
 * amdgpu: update psp 14.0.1 firmware
 * amdgpu: update gc 11.5.1 firmware
 * amdgpu: update vcn 4.0.5 firmware
 * amdgpu: update psp 14.0.0 firmware
 * amdgpu: update gc 11.5.0 firmware
 * amdgpu: update navi14 firmware
 * amdgpu: update arcturus firmware
 * amdgpu: update renoir firmware
 * amdgpu: update navi12 firmware
 * amdgpu: update sdma 4.4.2 firmware
 * amdgpu: update psp 13.0.6 firmware
 * amdgpu: update gc 9.4.3 firmware
 * amdgpu: update vcn 4.0.4 firmware
 * amdgpu: update psp 13.0.7 firmware
 * amdgpu: update gc 11.0.2 firmware
 * amdgpu: update navi10 firmware
 * amdgpu: update aldebaran firmware
- Update aliases from 6.13-rc1

- Update to version 20241125 (git commit 508d770ee6f3):
 * ice: update ice DDP wireless_edge package to 1.3.20.0
 * ice: update ice DDP comms package to 1.3.52.0
 * ice: update ice DDP package to ice-1.3.41.0
 * amdgpu: update DMCUB to v9.0.10.0 for DCN314
 * amdgpu: update DMCUB to v9.0.10.0 for DCN351

- Update to version 20241121 (git commit 48bb90cceb88):
 * linux-firmware: Update AMD cpu microcode
 * xe: Update GUC to v70.36.0 for BMG, LNL
 * i915: Update GUC to v70.36.0 for ADL-P, DG1, DG2, MTL, TGL

- Update to version 20241119 (git commit 60cdfe1831e8):
 * iwlwifi: add Bz-gf FW for core91-69 release
- Update aliases from 6.12

- Update to version 20241113 (git commit 1727aceef4d2):
 * qcom: venus-5.4: add venus firmware file for qcs615
 * qcom: update venus firmware file for ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-firmware' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-all", rpm:"kernel-firmware-all~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-amdgpu", rpm:"kernel-firmware-amdgpu~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath10k", rpm:"kernel-firmware-ath10k~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath11k", rpm:"kernel-firmware-ath11k~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath12k", rpm:"kernel-firmware-ath12k~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-atheros", rpm:"kernel-firmware-atheros~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bluetooth", rpm:"kernel-firmware-bluetooth~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bnx2", rpm:"kernel-firmware-bnx2~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-brcm", rpm:"kernel-firmware-brcm~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-chelsio", rpm:"kernel-firmware-chelsio~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-dpaa2", rpm:"kernel-firmware-dpaa2~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-i915", rpm:"kernel-firmware-i915~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-intel", rpm:"kernel-firmware-intel~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-iwlwifi", rpm:"kernel-firmware-iwlwifi~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-liquidio", rpm:"kernel-firmware-liquidio~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-marvell", rpm:"kernel-firmware-marvell~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-media", rpm:"kernel-firmware-media~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mediatek", rpm:"kernel-firmware-mediatek~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mellanox", rpm:"kernel-firmware-mellanox~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mwifiex", rpm:"kernel-firmware-mwifiex~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-network", rpm:"kernel-firmware-network~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nfp", rpm:"kernel-firmware-nfp~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia", rpm:"kernel-firmware-nvidia~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-platform", rpm:"kernel-firmware-platform~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-prestera", rpm:"kernel-firmware-prestera~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qcom", rpm:"kernel-firmware-qcom~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qlogic", rpm:"kernel-firmware-qlogic~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-radeon", rpm:"kernel-firmware-radeon~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-realtek", rpm:"kernel-firmware-realtek~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-serial", rpm:"kernel-firmware-serial~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-sound", rpm:"kernel-firmware-sound~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ti", rpm:"kernel-firmware-ti~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ueagle", rpm:"kernel-firmware-ueagle~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-usb-network", rpm:"kernel-firmware-usb-network~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd", rpm:"ucode-amd~20241128~150600.3.9.1", rls:"SLES15.0SP6"))) {
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
