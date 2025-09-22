# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

global_var prestashop_modules_info;

# nb:
# - The format is: "[MODULE_SLAG]", "[NAME]#---#[DETECTION PATTERN]#---#[VERSION REGEX]#---#[CPE]#---#[MODULE-PAGE PATH]"
# - To make sure that we're not using two or more entries for the same file in this array (When e.g.
#   having two entries the foreach(keys()) loop in the detection VT would iterate over both items
#   but the infos variable in both iterations would only include the info from one of both entries
#   two times) we can use something like e.g. the following:
#   egrep -o '^  "[^"]+",' prestashop_modules.inc | sort | uniq -d
#
prestashop_modules_info = make_array(
  "chronopost", "Chronopost official#---#<displayName><!\[CDATA\[Chronopost#---#<version><!\[CDATA\[([0-9.]+)\]\]><\/version>#---#cpe:/a:chronopost_official:chronopost_official#---#19561-chronopost-official",
  "dashproducts", "Dashboard Products#---#<displayName><!\[CDATA\[Dashboard Products#---#<version><!\[CDATA\[([0-9.]+)\]\]><\/version>#---#cpe:/a:prestashop:dashboard_products#---#15252-dashboard-products",
  "facebookconversiontrackingplus", "Pixel Plus: Events + CAPI + Pixel Catalog for Facebook#---#<displayName><!\[CDATA\[Facebook Conversion Tracking Pixel Plus#---#<version><!\[CDATA\[([0-9.]+)\]\]><\/version>#---#cpe:/a:smart_modules:pixel_plus_module#---#18739-pixel-plus-events-capi-pixel-catalog-for-facebook",
  "blockreassurance", "Customer reassurance#---#<displayName><!\[CDATA\[Customer reassurance block#---#<version><!\[CDATA\[([0-9.]+)\]\]><\/version>#---#cpe:/a:prestashop:customer_reassurance#---#22312-customer-reassurance");
