# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.857021");
  script_cve_id("CVE-2024-11218", "CVE-2024-36402", "CVE-2024-36403", "CVE-2024-45336", "CVE-2024-45339", "CVE-2024-45340", "CVE-2024-45341", "CVE-2024-51491", "CVE-2024-52281", "CVE-2024-52594", "CVE-2024-52602", "CVE-2024-52791", "CVE-2024-53263", "CVE-2024-56138", "CVE-2024-56323", "CVE-2024-56515", "CVE-2025-0377", "CVE-2025-20033", "CVE-2025-20086", "CVE-2025-20088", "CVE-2025-20621", "CVE-2025-21088", "CVE-2025-22149", "CVE-2025-22445", "CVE-2025-22449", "CVE-2025-22865", "CVE-2025-23028", "CVE-2025-23047", "CVE-2025-23208", "CVE-2025-24030", "CVE-2025-24337", "CVE-2025-24354", "CVE-2025-24355");
  script_tag(name:"creation_date", value:"2025-01-31 05:00:09 +0000 (Fri, 31 Jan 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-22 05:15:08 +0000 (Wed, 22 Jan 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0297-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0297-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250297-1.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020248.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'govulncheck-vulndb' package(s) announced via the SUSE-SU-2025:0297-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for govulncheck-vulndb fixes the following issues:

- Update to version 0.0.20250128T150132 2025-01-28T15:01:32Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2025-3409 CVE-2025-23208 GHSA-c9p4-xwr9-rfhx
 * GO-2025-3410 CVE-2025-24337 GHSA-3qc3-mx6x-267h
 * GO-2025-3413 CVE-2025-0377 GHSA-wpfp-cm49-9m9q
 * GO-2025-3414 CVE-2024-11218 GHSA-5vpc-35f4-r8w6
 * GO-2025-3415 CVE-2025-23028 GHSA-9m5p-c77c-f9j7
 * GO-2025-3416 CVE-2025-23047 GHSA-h78m-j95m-5356
 * GO-2025-3418 CVE-2025-24030 GHSA-j777-63hf-hx76
 * GO-2025-3419 CVE-2025-24355 GHSA-v34r-vj4r-38j6
 * GO-2025-3422 CVE-2025-24354

- Update to version 0.0.20250128T004730 2025-01-28T00:47:30Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2025-3372 CVE-2024-45339
 * GO-2025-3373 CVE-2024-45341
 * GO-2025-3383 CVE-2024-45340
 * GO-2025-3420 CVE-2024-45336
 * GO-2025-3421 CVE-2025-22865

- Update to version 0.0.20250117T214834 2025-01-17T21:48:34Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2025-3392 CVE-2025-20086 GHSA-5m7j-6gc4-ff5g
 * GO-2025-3393 CVE-2025-21088 GHSA-8j3q-gc9x-7972
 * GO-2025-3394 CVE-2025-20088 GHSA-45v9-w9fh-33j6
 * GO-2025-3396 CVE-2024-52594
 * GO-2025-3397 CVE-2024-36402 GHSA-8vmr-h7h5-cqhg
 * GO-2025-3398 CVE-2024-52791 GHSA-gp86-q8hg-fpxj
 * GO-2025-3399 CVE-2024-52602 GHSA-r6jg-jfv6-2fjv
 * GO-2025-3400 CVE-2024-56515 GHSA-rcxc-wjgw-579r
 * GO-2025-3401 CVE-2024-36403 GHSA-vc2m-hw89-qjxf
 * GO-2025-3407 CVE-2025-20621 GHSA-w6xh-c82w-h997

- Update to version 0.0.20250115T172141 2025-01-15T17:21:41Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2025-3381 CVE-2024-56138 GHSA-45v3-38pc-874v
 * GO-2025-3382 CVE-2024-51491 GHSA-qjh3-4j3h-vmwp
 * GO-2025-3384 CVE-2024-56323 GHSA-32q6-rr98-cjqv
 * GO-2025-3390 CVE-2024-53263 GHSA-q6r2-x2cc-vrp7
 * GO-2025-3391 CVE-2024-52281 GHSA-2v2w-8v8c-wcm9

- Update to version 0.0.20250109T194159 2025-01-09T19:41:59Z.
 Refs jsc#PED-11136
 Go CVE Numbering Authority IDs added or updated with aliases:
 * GO-2025-3376 CVE-2025-22149 GHSA-675f-rq2r-jw82
 * GO-2025-3377 CVE-2025-22449 GHSA-q8fg-cp3q-5jwm
 * GO-2025-3379 CVE-2025-20033 GHSA-2549-xh72-qrpm
 * GO-2025-3380 CVE-2025-22445 GHSA-7rgp-4j56-fm79");

  script_tag(name:"affected", value:"'govulncheck-vulndb' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"govulncheck-vulndb", rpm:"govulncheck-vulndb~0.0.20250128T150132~150000.1.29.1", rls:"openSUSELeap15.6"))) {
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
