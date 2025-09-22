# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856692");
  script_cve_id("CVE-2022-45157", "CVE-2023-22644", "CVE-2023-32197", "CVE-2024-10214", "CVE-2024-10241", "CVE-2024-22030", "CVE-2024-22036", "CVE-2024-33662", "CVE-2024-36814", "CVE-2024-38365", "CVE-2024-39223", "CVE-2024-47003", "CVE-2024-47067", "CVE-2024-47182", "CVE-2024-47534", "CVE-2024-47616", "CVE-2024-47825", "CVE-2024-47827", "CVE-2024-47832", "CVE-2024-47877", "CVE-2024-48909", "CVE-2024-48921", "CVE-2024-49380", "CVE-2024-49381", "CVE-2024-49753", "CVE-2024-49757", "CVE-2024-50312", "CVE-2024-7558", "CVE-2024-7594", "CVE-2024-8037", "CVE-2024-8038", "CVE-2024-8901", "CVE-2024-8975", "CVE-2024-8996", "CVE-2024-9180", "CVE-2024-9264", "CVE-2024-9312", "CVE-2024-9313", "CVE-2024-9341", "CVE-2024-9355", "CVE-2024-9407", "CVE-2024-9486", "CVE-2024-9594", "CVE-2024-9675");
  script_tag(name:"creation_date", value:"2024-11-06 05:00:28 +0000 (Wed, 06 Nov 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-08 20:51:31 +0000 (Fri, 08 Nov 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3911-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3911-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243911-1.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019776.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'govulncheck-vulndb' package(s) announced via the SUSE-SU-2024:3911-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for govulncheck-vulndb fixes the following issues:

Update to version 0.0.20241030T212825 2024-10-30T21:28:25Z ( jsc#PED-11136 )

- Go CVE Numbering Authority IDs added or updated with aliases:

 * GO-2024-3230 CVE-2024-48921 GHSA-qjvc-p88j-j9rm
 * GO-2024-3232 CVE-2024-10241 GHSA-6mvp-gh77-7vwh

- Go CVE Numbering Authority IDs added or updated with aliases:

 * GO-2024-3226 CVE-2024-47827 GHSA-ghjw-32xw-ffwr
 * GO-2024-3227 CVE-2024-10214 GHSA-hm57-h27x-599c
 * GO-2024-3228 GHSA-wcx9-ccpj-hx3c

- Go CVE Numbering Authority IDs added or updated with aliases:

 * GO-2024-3207 GHSA-p5wf-cmr4-xrwr
 * GO-2024-3208 CVE-2024-47825 GHSA-3wwx-63fv-pfq6
 * GO-2024-3210 CVE-2024-8901
 * GO-2024-3211 CVE-2024-50312
 * GO-2024-3212 GHSA-rjfv-pjvx-mjgv
 * GO-2024-3213 CVE-2024-49380
 * GO-2024-3214 CVE-2024-49381
 * GO-2024-3215 CVE-2024-9264 GHSA-q99m-qcv4-fpm7
 * GO-2024-3216 CVE-2024-49753 GHSA-6cf5-w9h3-4rqv
 * GO-2024-3217 CVE-2024-49757 GHSA-3rmw-76m6-4gjc
 * GO-2024-3219 GHSA-7h65-4p22-39j6
 * GO-2024-3220 CVE-2023-32197 GHSA-7h8m-pvw3-5gh4
 * GO-2024-3221 CVE-2024-22036 GHSA-h99m-6755-rgwc
 * GO-2024-3222 GHSA-x7xj-jvwp-97rv
 * GO-2024-3223 CVE-2022-45157 GHSA-xj7w-r753-vj8v
 * GO-2024-3224 CVE-2024-39223 GHSA-8wxx-35qc-vp6r

- Go CVE Numbering Authority IDs added or updated with aliases:

 * GO-2024-3189 CVE-2024-38365 GHSA-27vh-h6mc-q6g8
 * GO-2024-3203 CVE-2024-9486
 * GO-2024-3204 CVE-2024-9594

- Go CVE Numbering Authority IDs added or updated with aliases:

 * GO-2024-3189 CVE-2024-38365 GHSA-27vh-h6mc-q6g8
 * GO-2024-3196 CVE-2024-47877 GHSA-8rm2-93mq-jqhc
 * GO-2024-3199 GHSA-vv6c-69r6-chg9
 * GO-2024-3200 CVE-2024-48909 GHSA-3c32-4hq9-6wgj
 * GO-2024-3201 CVE-2023-22644
- Go CVE Numbering Authority IDs added or updated with aliases:

 * GO-2024-3166 CVE-2024-47534 GHSA-4f8r-qqr9-fq8j
 * GO-2024-3171 CVE-2024-9341 GHSA-mc76-5925-c5p6

- Go CVE Numbering Authority IDs added or updated with aliases:

 * GO-2024-3161 CVE-2024-22030 GHSA-h4h5-9833-v2p4
 * GO-2024-3162 CVE-2024-7594 GHSA-jg74-mwgw-v6x3
 * GO-2024-3163 CVE-2024-47182
 * GO-2024-3164 CVE-2024-47003 GHSA-59hf-mpf8-pqjh
 * GO-2024-3166 CVE-2024-47534 GHSA-4f8r-qqr9-fq8j
 * GO-2024-3167 CVE-2024-9355 GHSA-3h3x-2hwv-hr52
 * GO-2024-3168 CVE-2024-8975 GHSA-chqx-36rm-rf8h
 * GO-2024-3169 CVE-2024-9407 GHSA-fhqq-8f65-5xfc
 * GO-2024-3170 CVE-2024-8996 GHSA-m5gv-m5f9-wgv4
 * GO-2024-3172 CVE-2024-33662 GHSA-9mjw-79r6-c9m8
 * GO-2024-3173 CVE-2024-7558 GHSA-mh98-763h-m9v4
 * GO-2024-3174 CVE-2024-8037 GHSA-8v4w-f4r9-7h6x
 * GO-2024-3175 CVE-2024-8038 GHSA-xwgj-vpm9-q2rq
 * GO-2024-3179 CVE-2024-47616 GHSA-r7rh-jww5-5fjr
 * GO-2024-3181 CVE-2024-9313 GHSA-x5q3-c8rm-w787
 * GO-2024-3182 GHSA-wpr2-j6gr-pjw9
 * GO-2024-3184 CVE-2024-36814 GHSA-9cp9-8gw2-8v7m
 * GO-2024-3185 CVE-2024-47832
 * GO-2024-3186 CVE-2024-9675 GHSA-586p-749j-fhwp
 * GO-2024-3188 CVE-2024-9312 GHSA-4gfw-wf7c-w6g2
 * GO-2024-3190 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'govulncheck-vulndb' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"govulncheck-vulndb", rpm:"govulncheck-vulndb~0.0.20241030T212825~150000.1.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"govulncheck-vulndb", rpm:"govulncheck-vulndb~0.0.20241030T212825~150000.1.9.1", rls:"openSUSELeap15.6"))) {
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
