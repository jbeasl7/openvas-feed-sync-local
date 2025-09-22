# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3341.1");
  script_cve_id("CVE-2021-25743", "CVE-2023-2727", "CVE-2023-2728", "CVE-2023-39325", "CVE-2023-44487", "CVE-2023-45288", "CVE-2024-0793", "CVE-2024-24786", "CVE-2024-3177");
  script_tag(name:"creation_date", value:"2024-09-20 04:26:49 +0000 (Fri, 20 Sep 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-17 11:15:06 +0000 (Sun, 17 Nov 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3341-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3341-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243341-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230323");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-September/036982.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kubernetes1.23' package(s) announced via the SUSE-SU-2024:3341-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kubernetes1.23 fixes the following issues:

- CVE-2021-25743: escape, meta and control sequences in raw data output to terminal not neutralized. (bsc#1194400)
- CVE-2023-2727: bypass of policies imposed by the ImagePolicyWebhook admission plugin. (bsc#1211630)
- CVE-2023-2728: bypass of the mountable secrets policy enforced by the ServiceAccount admission plugin. (bsc#1211631)
- CVE-2023-39325: go1.20: excessive resource consumption when dealing with rapid stream resets. (bsc#1229869)
- CVE-2023-44487: google.golang.org/grpc, kube-apiserver: HTTP/2 rapid reset vulnerability. (bsc#1229869)
- CVE-2023-45288: golang.org/x/net: excessive CPU consumption when processing unlimited sets of headers. (bsc#1229869)
- CVE-2024-0793: kube-controller-manager pod crash when processing malformed HPA v1 manifests. (bsc#1219964)
- CVE-2024-3177: bypass of the mountable secrets policy enforced by the ServiceAccount admission plugin. (bsc#1222539)
- CVE-2024-24786: github.com/golang/protobuf: infinite loop when unmarshaling invalid JSON. (bsc#1229867)

Bug fixes:

- Use -trimpath in non-DBG mode for reproducible builds. (bsc#1062303)
- Fix multiple issues for successful `kubeadm init` run. (bsc#1214406)
- Update go to version 1.22.5 in build requirements. (bsc#1229858)");

  script_tag(name:"affected", value:"'kubernetes1.23' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client", rpm:"kubernetes1.24-client~1.24.17~150400.9.16.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kubernetes1.24-client-common", rpm:"kubernetes1.24-client-common~1.24.17~150400.9.16.1", rls:"SLES15.0SP4"))) {
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
