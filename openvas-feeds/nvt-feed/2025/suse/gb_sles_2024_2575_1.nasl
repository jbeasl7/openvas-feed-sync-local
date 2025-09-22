# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2575.1");
  script_cve_id("CVE-2023-38417", "CVE-2023-47210");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2575-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2575-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242575-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225601");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-July/036099.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware' package(s) announced via the SUSE-SU-2024:2575-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:

- CVE-2023-38417: Fixed improper input validation for some Intel(R) PROSet/Wireless WiFi software for linux before version 23.20 (bsc#1225600)
- CVE-2023-47210: Fixed improper input validation for some Intel(R) PROSet/Wireless WiFi software before version 23.20 (bsc#1225601)

- Update to version 20240712 (git commit ed874ed83cac):
 * amdgpu: update DMCUB to v0.0.225.0 for Various AMDGPU Asics
 * qcom: add gpu firmwares for x1e80100 chipset (bsc#1219458)
 * linux-firmware: add firmware for qat_402xx devices
 * amdgpu: update raven firmware
 * amdgpu: update SMU 13.0.10 firmware
 * amdgpu: update SDMA 6.0.3 firmware
 * amdgpu: update PSP 13.0.10 firmware
 * amdgpu: update GC 11.0.3 firmware
 * amdgpu: update vega20 firmware
 * amdgpu: update PSP 13.0.5 firmware
 * amdgpu: update PSP 13.0.8 firmware
 * amdgpu: update vega12 firmware
 * amdgpu: update vega10 firmware
 * amdgpu: update VCN 4.0.0 firmware
 * amdgpu: update SDMA 6.0.0 firmware
 * amdgpu: update PSP 13.0.0 firmware
 * amdgpu: update GC 11.0.0 firmware
 * amdgpu: update picasso firmware
 * amdgpu: update beige goby firmware
 * amdgpu: update vangogh firmware
 * amdgpu: update dimgrey cavefish firmware
 * amdgpu: update navy flounder firmware
 * amdgpu: update PSP 13.0.11 firmware
 * amdgpu: update GC 11.0.4 firmware
 * amdgpu: update green sardine firmware
 * amdgpu: update VCN 4.0.2 firmware
 * amdgpu: update SDMA 6.0.1 firmware
 * amdgpu: update PSP 13.0.4 firmware
 * amdgpu: update GC 11.0.1 firmware
 * amdgpu: update sienna cichlid firmware
 * amdgpu: update VPE 6.1.1 firmware
 * amdgpu: update VCN 4.0.6 firmware
 * amdgpu: update SDMA 6.1.1 firmware
 * amdgpu: update PSP 14.0.1 firmware
 * amdgpu: update GC 11.5.1 firmware
 * amdgpu: update VCN 4.0.5 firmware
 * amdgpu: update SDMA 6.1.0 firmware
 * amdgpu: update PSP 14.0.0 firmware
 * amdgpu: update GC 11.5.0 firmware
 * amdgpu: update navi14 firmware
 * amdgpu: update renoir firmware
 * amdgpu: update navi12 firmware
 * amdgpu: update PSP 13.0.6 firmware
 * amdgpu: update GC 9.4.3 firmware
 * amdgpu: update yellow carp firmware
 * amdgpu: update VCN 4.0.4 firmware
 * amdgpu: update SMU 13.0.7 firmware
 * amdgpu: update SDMA 6.0.2 firmware
 * amdgpu: update PSP 13.0.7 firmware
 * amdgpu: update GC 11.0.2 firmware
 * amdgpu: update navi10 firmware
 * amdgpu: update raven2 firmware
 * amdgpu: update aldebaran firmware
 * linux-firmware: Update AMD cpu microcode
 * linux-firmware: Add ISH firmware file for Intel Lunar Lake platform
 * amdgpu: update DMCUB to v0.0.224.0 for Various AMDGPU Asics
 * cirrus: cs35l41: Update various firmware for ASUS laptops using CS35L41
 * amdgpu: Update ISP FW for isp v4.1.1

- Update to version 20240622 (git commit 7d931f8afa51):
 * linux-firmware: mediatek: Update MT8173 VPU firmware to v1.2.0
 * qcom: Add AIC100 firmware files

- Update to version 20240618 (git ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-all", rpm:"kernel-firmware-all~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-amdgpu", rpm:"kernel-firmware-amdgpu~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath10k", rpm:"kernel-firmware-ath10k~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath11k", rpm:"kernel-firmware-ath11k~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ath12k", rpm:"kernel-firmware-ath12k~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-atheros", rpm:"kernel-firmware-atheros~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bluetooth", rpm:"kernel-firmware-bluetooth~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-bnx2", rpm:"kernel-firmware-bnx2~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-brcm", rpm:"kernel-firmware-brcm~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-chelsio", rpm:"kernel-firmware-chelsio~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-dpaa2", rpm:"kernel-firmware-dpaa2~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-i915", rpm:"kernel-firmware-i915~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-intel", rpm:"kernel-firmware-intel~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-iwlwifi", rpm:"kernel-firmware-iwlwifi~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-liquidio", rpm:"kernel-firmware-liquidio~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-marvell", rpm:"kernel-firmware-marvell~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-media", rpm:"kernel-firmware-media~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mediatek", rpm:"kernel-firmware-mediatek~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mellanox", rpm:"kernel-firmware-mellanox~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-mwifiex", rpm:"kernel-firmware-mwifiex~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-network", rpm:"kernel-firmware-network~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nfp", rpm:"kernel-firmware-nfp~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-nvidia", rpm:"kernel-firmware-nvidia~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-platform", rpm:"kernel-firmware-platform~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-prestera", rpm:"kernel-firmware-prestera~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qcom", rpm:"kernel-firmware-qcom~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-qlogic", rpm:"kernel-firmware-qlogic~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-radeon", rpm:"kernel-firmware-radeon~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-realtek", rpm:"kernel-firmware-realtek~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-serial", rpm:"kernel-firmware-serial~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-sound", rpm:"kernel-firmware-sound~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ti", rpm:"kernel-firmware-ti~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-ueagle", rpm:"kernel-firmware-ueagle~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware-usb-network", rpm:"kernel-firmware-usb-network~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd", rpm:"ucode-amd~20240712~150600.3.3.1", rls:"SLES15.0SP6"))) {
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
