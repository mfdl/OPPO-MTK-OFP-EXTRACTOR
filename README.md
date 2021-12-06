# OPPO MTK OFP EXTRACTOR
 Extract OPPO mtk ofp files + multi region/nv super image support.
* support multi region super images (merge - append).
* for multi super case you need to flash only 1 super file (1 region) check the correct region for your phone .
* then rename SUPER_XX to super.img +
* open scatter file via notepad and edit is_download: false to is_download: true.
* select preloader manually from extraction folder.
* XX = region.
* for example :
* DZ = Algeria.
* IN = India.
* VN = Vietnam.
* extraction algo credit to @Bjoern Kerler. ported from https://github.com/bkerler/oppo_decrypt.
